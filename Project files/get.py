def get(sock, usr_in):   #client
    params = usr_in.split(" ")
    try:
        filepath = params[1]
        flag = params[2]	
        if flag == 'E':
            password = params[3]
            assert len(password) == 8
        else:
            assert flag == 'N'
    except (IndexError, AssertionError):
        print("Please specify a filepath, flag that is E or N, and, if the flag is E, an 8-character password")
        return

    try:
        sock.sendall("get "+filepath)
        resp = sock.recv(1024)
        if resp == "Not a good request":
            print("The file cannot be retrieved. Get failed.")
            return
        sock.sendall("ack")
        size = int(sock.recv(1024))    #Receives length of message
        #words = response.split()
        #if cannot in words:
        #return
        #size = bytes_to_number(count)
        current_size = 0
        buffer = b""
        while current_size < size:
            data = sock.recv(1024)//receiving 
            if not data:
               break
       	    if len(data) + current_size > size:
               data = data[:size-current_size] # trim additional data
            buffer += data
            current_size += len(data)
        ciphertext = buffer
        hash = sock.recv(1024) #Receiving the hash file from the server
        sock.sendall("ack")
        if flag == 'E':
	    salt = 'some arbitrary value'
            key = hashlib.pbkdf2_hmac('sha256', bytearray(password), bytearray(salt), 100001, dklen=16)
            iv = ciphertext[:AES.block_size] # generate an IV
            ciphertext = ciphertext[AES.block_size:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext)
            plaintext = plaintext[:-ord(plaintext[-1])]
	
	else:
	    plaintext = ciphertext

        hsh = SHA256.new(plaintext)
        hashtext = hsh.digest() #create the hash of the decrypted plaintext
        if (hash == hashtext):
	    with open(filename, 'wb') as f: #except for cannot write
            f.write(text)
        else:
	    print("The hashes did not match") 
	    return

    except socket.error:
        print("Connection to the remote host was lost. Get could not be completed")

def get(conn, mode):
    filename = mode.split()[1]
    try:
        with open(filename, 'rb') as f:
            data = f.read()
        with open(filename+".sha256", 'rb') as f:
            hsh = f.read()
    except:
        conn.sendall("badreq")
        return
    conn.sendall("get ok")
    resp = conn.recv(1024)
    length = os.path.getsize(filename)
    client.send(length) # has to be 4 bytes
    resp = conn.recv(1024)
    with open(filename, 'r') as infile:
        d = infile.read(1024)
        while d:
            client.send(d)
            d = infile.read(1024)
    conn.sendall(hsh)
    resp = conn.recv(1024)
    '''blocknum = int(sys.getsizeof(data) / 4096)
    conn.sendall(str(blocknum))
    resp = conn.recv(1024)
    while blocknum >= 0:
        conn.sendall(data[:4096])
        data = data[4096:]
        blocknum -= 1'''

def convert_to_bytes(no):
    result = bytearray()
    result.append(no & 255)
    for i in range(3):
        no = no >> 8
        result.append(no & 255)
    return result

def bytes_to_number(b):
    # if Python2.x
    # b = map(ord, b)
    res = 0
    for i in range(4):
        res += b[i] << (i*8)
    return res     		
