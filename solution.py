from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2


# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(str):
# In this function we make the checksum of our packet. hint: see icmpPing lab
    csum = 0
    countTo = (len(str) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = str[count + 1] * 256 + str[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(str):
        csum = csum + str[len(str) - 1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def build_packet():
    # Fill in start
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.

    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.

    # Don’t send the packet yet , just return the final packet in this function.

    ID = os.getpid() & 0xFFFF  # Return the current process i

    myChecksum = 0
    # Make a dummy header with a 0 checksum.
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)
    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
        # Convert 16-bit integers from host to network byte order.
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)

    #Fill in end

    # So the function ending should look like this
    packet = header + data
    return packet


def get_route(hostname):

    timeLeft = TIMEOUT
    tracelist1 = [] #This is your list to use when iterating through each trace
    tracelist2 = [] #This is your list to contain all traces

    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)
            # Fill in start
            # Make a raw socket named mySocket
            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)

            #try:
             #   mySocket = socket(AF_INET, SOCK_RAW, icmp)
            #except error as msg:
             #   print("Socket create error:", msg)
            # Fill in end


            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []:  # Timeout
                    tracelist1.append("* * * Request timed out.")
                    tracelist2.append(tracelist1)
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()

                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    tracelist1.append("* * * Request timed out.")
                    #Fill in start
                    tracelist2.append(tracelist1)
                    # Fill in start
            except timeout:
                continue
            else:
                # Fill in start
                # Fetch the icmp type from the IP packet
                icmpHeader = recvPacket[20:28]
                types, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
                # Fill in end

                # get RTT in ms
                rtt = (timeReceived - struct.unpack("d", recvPacket[28:36])[0]) * 1000


                try:#try to fetch the hostname
                    #Fill in start
                    hostaddr = gethostbyaddr(addr[0])[0]
                    # Fill in end

                except herror:  #if the host does not provide a hostname
                    # Fill in start
                    hostaddr = "hostname not returnable"
                    # Fill in end

                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start
                    string_addr = str(addr[0])
                    string_ttl = str(ttl)
                    string_ms= str((timeReceived - t) * 1000)
                    tracelist2.append((string_ttl,string_ms,string_addr,hostaddr))
                    #print("%d\t%.0f ms\t%s\t%s" % (ttl, (timeReceived - t) * 1000, addr[0], hostaddr))
                    # Fill in end
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start
                    string_addr = str(addr[0])
                    string_ttl = str(ttl)
                    string_ms = str((timeReceived - t) * 1000)
                    tracelist2.append((string_ttl, string_ms, string_addr, hostaddr))
                    #print("%d\t%.0f ms\t%s\t%s" % (ttl, (timeReceived - t) * 1000, addr[0], hostaddr))
                    # Fill in end

                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start
                    string_addr = str(addr[0])
                    string_ttl = str(ttl)
                    string_ms = str((timeReceived - t) * 1000)
                    tracelist2.append((string_ttl, string_ms, string_addr, hostaddr))
                    #print("%d\t%.0f ms\t%s\t%s" % (ttl, (timeReceived - timeSent) * 1000, addr[0], hostaddr))
                    # Fill in end
                else:
                    # Fill in start
                    print("error")
                    # Fill in end
                break
            finally:
                mySocket.close()
    return (tracelist2)


#Traceroute
if __name__ == '__main__':
    get_route("google.com")
