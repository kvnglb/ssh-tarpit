import ast
import hashlib
import io
import os
from queue import Queue
import random
import socket
import threading
import time

import psycopg2


SERVER_INIT_KEX_DATA = [b"curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,",
                        b"ssh-ed25519,ssh-dss,",
                        b"aes256-ctr,3des-cbc,",
                        b"aes256-ctr,3des-cbc,",
                        b"hmac-sha2-256,hmac-sha1,",
                        b"hmac-sha2-256,hmac-sha1,",
                        b"none,",
                        b"none,",
                        b"",
                        b""]

CHARS_FOR_KEX = "abcdefghijklmnopqrstuvwxyz0123456789,"


class SSHtarpit:
    def __init__(self, ip, port, db_cur_w, db_cur_r):
        """Initialize the tarpit.

        Parameters
        ----------
        ip : str
            IP address, where the tarpit should listen.
        port : int
            Port, which should be used for the tarpit.
        db_cur_w : psycopg2.connect.cursor
            Cursor, that is used to write the db.
        db_cur_r : psycopg2.connect.cursor
            Cursor, that is used to read the db.

        Attributes
        ----------
        ip : type(ip)
            descr(ip)
        port : type(port)
            descr(prot)
        db_cur_w : type(db_cur_w)
            descr(db_cur_w)
        db_cur_r : type(db_cur_r)
            descr(db_cur_r)
        max_conn : int
            Number of connections (threads), that this script will tarpit.
        ip_max_conn : int
            Number of connections, that this script will tarpit from the
            same IP address.
        q_db : queue.Queue
            Everything put in here will be written to the db by db_cur_w.
        q_log : queue.Queue
            Everything put in here will be written to the log.

        """
        self.ip = ip
        self.port = port
        self.db_cur_w = db_cur_w
        self.db_cur_r = db_cur_r
        self.max_conn = int(os.environ.get("MAX_CONN"))
        self.ip_max_conn = int(os.environ.get("IP_MAX_CONN"))
        self.q_db = Queue()
        self.q_log = Queue()

    def serve(self):
        """The main thread serving the tarpit and waiting for connections.

        Start both threads, the one to write the database and the one to
        write the log file. After, it binds the socket and waits for
        incoming connections.

        When a connections occurs, and the maximum connections are not reached
        (both in total and for this IP address), the tarpit thread is started
        and the connection is handled in this new thread.

        Attributes
        ----------
        s : socket.socket
            The TCP socket for the ssh tarpit.

        """
        threading.Thread(target=self.write_db, daemon=True).start()
        threading.Thread(target=self.write_log, daemon=True).start()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.ip, self.port))
        self.s.listen(0)

        while True:
            if len(threading.enumerate()) < self.max_conn + 3:
                conn, addr = self.s.accept()
                self.db_cur_r.execute("SELECT id FROM ip WHERE address = %s AND timespan IS NULL;",
                                      (addr[0][:45],))
                ip_id = self.db_cur_r.fetchall()
                if len(ip_id) >= self.ip_max_conn:
                    conn.close()
                    self.q_log.put([addr[0], "Max tarpits of {} for ip reached".format(self.ip_max_conn)])
                else:
                    conn.settimeout(5)
                    threading.Thread(target=self.tarpit, args=(conn, addr), daemon=True).start()
            else:
                time.sleep(10)
                self.q_log.put(["0.0.0.0", "Max connections of {} exceeded".format(self.max_conn)])

    def write_db(self):
        """Write the begin and end of a connection to the db, with information from the queue."""

        while True:
            start, addr, ident, service, tarpit = self.q_db.get()
            if start:
                self.db_cur_w.execute("INSERT INTO ip (address, identifier, service, tarpit) VALUES (%s, %s, %s, %s);",
                                      (addr[:45], ident, service[:45], tarpit))
            else:
                self.db_cur_w.execute("UPDATE ip SET timespan = (CURRENT_TIMESTAMP - time) WHERE address = %s AND identifier = %s;",
                                      (addr[:45], ident))

    def write_log(self):
        """"Write the log based on the queue."""
        while True:
            addr, err = self.q_log.get()
            with open("log/ssh.log", "a") as f:
                f.write("{}\t{}\t{}\n".format(time.strftime("%Y-%m-%d %H:%M"), addr, err))
                f.flush()

    def tarpit(self, conn, addr):
        """Run as thread and tarpit the connection.

        Based on the implemented methods and the configuration in the compose file,
        it is randomly choosed which tarpit is used.

        But when the connection does not initialize the SSH handshake, the
        connection is closed immediately without writing in the db but in the log.

        Parameters
        ----------
        conn : socket.connection
            The connection of the tarpited client.
        addr : socket.address
            The address of the tarpited client.

        """
        try:
            data = conn.recv(1024)
            data_dec = data.replace(b"\r", b"").replace(b"\n", b"").decode("utf-8")
        except Exception as e:
            conn.close()
            self.q_log.put([addr[0], e])
            return

        if not (data[:5] == b"SSH-2" and data[-1:] == b"\n"):
            conn.close()
            self.q_log.put([addr[0], "No ssh init: {}".format(data)])
            return

        tarpit = random.choice(ast.literal_eval(os.environ.get("SSH_TARPIT")))

        ident = hashlib.md5("{}+{}".format(addr[0], time.time()).encode("ascii")).hexdigest()
        self.q_db.put([True, addr[0], ident, data_dec, tarpit])

        try:
            if tarpit == "banner":
                self.tarpit_banner(conn)
            elif tarpit == "kex":
                self.tarpit_kex(conn, addr)
        except Exception:
            pass

        conn.close()
        self.q_db.put([False, addr[0], ident, None, None])

    def tarpit_banner(self, conn):
        """Send infinitely random bytes to the client, that established a valid SSH connection.

        Send random bytes but never the correct SSH response to trigger the key exchange.

        Parameters
        ----------
        conn : type(tarpit:conn)
            descr(tarpit:conn)

        """
        while True:
            length_line = 230 + random.randint(0, 20)

            while length_line > 0:
                length_bytes = random.randint(1, 4)
                if length_bytes > length_line:
                    length_bytes = length_line

                send_bytes = b""
                for i in range(length_bytes):
                    send_bytes += bytes.fromhex(hex(random.randint(97, 122))[2:])

                conn.send(send_bytes)
                length_line -= length_bytes
                time.sleep(random.randint(0, 50)/10)

            conn.send(b"\r")
            time.sleep(random.randint(0, 30)/10)
            conn.send(b"\n")
            time.sleep(random.randint(0, 100)/10)

    def tarpit_kex(self, conn, addr):
        """Send a very long name list for 'algorithms', where client and server can agree on.

        This tarpit works at kex level and sends a very long kex response, where normally
        server and client agree on algorithms. Besides a few valid algorithms (where this
        script only claims it is able to handle these), some weird gibberish is sent.

        According to the spec, the string could be theoretically 2^32 bytes long.
        Unfortunately, there are some restrictions in 6.1 [RFC4253]. Anyway, libssh
        can handle larger packet lengths than the minimal requirement (35000 bytes);
        tarpit_kex is based on this number.

        Parameters
        ----------
        conn : type(tarpit:conn)
            descr(tarpit:conn)
        addr : type(tarpit:addr)
            descr(tarpit:addr)

        """
        s = io.BytesIO(b"SSH-2.0-OpenSSH_7'); DROP TABLE ip;--")
        while True:
            data = s.read(random.randint(1, 5))
            if data:
                conn.send(data)
                time.sleep(random.randint(0, 10)/10)
            else:
                break

        data = b""
        for i in range(800):
            data += bytes.fromhex(hex(random.randint(97, 122))[2:])
            if not random.randint(0, 3):
                conn.send(data)
                data = b""
                time.sleep(random.randint(1, 10)/10)
        data += b"\r\n"
        conn.send(data)

        packet_length = int.from_bytes(conn.recv(4), "big")

        if packet_length > 35000:
            self.q_log.put([addr[0], "packet_length {} too long".format(packet_length)])
            return

        conn.recv(packet_length)  # ignore the received packet, because we do not plan to agree on anything
        kex_payload_length = 220000 + random.randint(0, 20000)

        bs = 8
        padding_length = bs - ((5 + kex_payload_length) % bs)
        padding_length = padding_length if padding_length >= 4 else padding_length + bs
        random_padding = random.randbytes(padding_length)

        # first four bytes (uint32) is the length of the whole kex init string
        # The complete length is the sum of
        #   - the length of kex_payload
        #   - 1, a byte that contains the length of the random_padding
        #   - the length of random_padding
        data = int.to_bytes(kex_payload_length + 1 + padding_length, 4, "big")

        # the 5th byte is the length of the random_padding
        data += int.to_bytes(padding_length, 1, "big")

        # kex begins at the 6th byte and starts with the number for SSH_MSG_KEXINIT
        data += b"\x14"

        # 16 bytes for the cookie follow
        data += random.randbytes(16)

        # fun begins here, because name-lists can be long
        kex_payload_length -= 22  # 22 bytes are fixed, the rest can be used in the name-lists
        length_line_init = kex_payload_length // 10
        for i in range(10):
            length_line = length_line_init + random.randint(0, 20)

            kex_line = SERVER_INIT_KEX_DATA[i]
            length_fixed = len(kex_line)

            if i <= 8:
                length_rem = length_line - length_fixed
                kex_payload_length -= length_line
            else:
                length_rem = kex_payload_length - length_fixed

            data += int.to_bytes(length_rem + length_fixed - 4, 4, "big") + kex_line
            for j in range(length_rem - 4):
                data += random.choice(CHARS_FOR_KEX).encode("ascii")
                if not random.randint(0, 3):
                    conn.send(data)
                    data = b""
                    time.sleep(random.randint(1, 20)/10)

        # kex ends with the last 5 fixed bytes (1 byte is
        # first_kex_packet_follows, 4 bytes are reserved)
        data += 5 * b"\x00"

        # finally, the random padding for an unencrypted message
        data += random_padding

        # conn.send(data)  # as if...


while True:
    try:
        db_conn = psycopg2.connect(user="ssh", password=os.environ.get("POSTGRES_SSH_PASSWORD"),
                                   database="ssh", host="127.0.0.1", port=int(os.environ.get("POSTGRES_PORT")))
        break
    except Exception:
        time.sleep(2)

db_conn.autocommit = True
db_cur_w = db_conn.cursor()
db_cur_r = db_conn.cursor()

print("Connected to db")
ssh = SSHtarpit(os.environ.get("SSH_IP_ADDR"), int(os.environ.get("SSH_PORT")), db_cur_w, db_cur_r)
ssh.serve()
