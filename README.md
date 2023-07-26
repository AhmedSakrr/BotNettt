# Intro
In this project we implemented a client-sserver botnet protocol with DDos and DHCP stravation capeabilities
We created a protocol to enable the master-slave communication and funconalities using TCP and multicast.
Written in C.
# Bots
The bots establish communication with the master through a TCP channel and remain on standby, awaiting multicast messages to determine the timing and manner for desired  attack.
# Master
the "Master" component controls the bots and initiates attacks based on user inputs.
# Attacks
## DDoS by SYN-attack:
This attack involves overwhelming the targeted server with an overflow of SYN requests. As a result, the server's ability to handle legitimate       requests will be severely affected. For example, if the server is in the process of transferring a file to a client, the DDoS attack will            disrupt the communication and slow down the transfer significantly. Additionally, the server might become unresponsive to pinging attempts due       to the excessive SYN requests.
## DHCP Starvation:
In this attack, the DHCP server is flooded with broadcast DHCP request messages. As a consequence, all the available IP addresses in the DHCP        server's pool are rapidly assigned, even though there are no actual clients making requests. Consequently, the DHCP binding table becomes full,      and any new client attempting to acquire an IP address from the DHCP server will be unsuccessful in obtaining one.
# Protocol
The protocol consists 4 stages:

1. **OPEN**: In this step, the bot establishes a TCP connection with the server. During the verification phase, the bot sends a "HELLO" message to the server. Upon successful verification, the server responds with an "ACK" message containing the ID assigned to the bot. The bot then performs an NMAP scan on its network and sends the results back to the server in a "REPORT" message. If everything is in order, the server responds with another "ACK" message containing the Multicast address that the bot needs to join.

2. **ESTABLISH**: After joining the Multicast group, the bot enters this stage. Every 30 seconds, the server sends a "KEEPALIVE" message to the bots, and they respond with a "KEEPALIVE" message through TCP. If the bot receives a Multicast message of type "REQUEST," it transitions to the next step.

3. **ATTACK**: At this stage, the bots receive an attack command from the server in a "REQUEST" message. During this phase, the server and bots stop exchanging "KEEPALIVE" messages with each other, assuming regular network communication will not be expected due to the ongoing attack. The bot sets a TIMER for the duration of the attack, as determined by the attacker. At the end of the attack period, the bot reports the completion of the attack by sending a "REPORT" message and returns to the "ESTABLISH" phase.

4. **ABORT**: If any errors occur during the steps mentioned above, the server or bot terminates the connection. It is important to note that when the last bot belonging to the Multicast group leaves, the server closes the group.

# Robustness Mechaninsms
We manged to handle the upcoming situations:

1. **Fake Bot**: We examined how the protocol deals with a malicious bot attempting to connect and sending a non-standard "HELLO" message. Rest assured, the protocol swiftly detects such abnormal behavior and initiates the "ABORT" state, effectively disconnecting the unauthorized bot.

2. **Delayed NMAP**: To ensure smooth operation, we tested what happens when a bot fails to send its NMAP results within the specified time frame (controlled by a timer). The protocol demonstrated its adaptability by handling the delay gracefully, preventing any disruptions in the communication flow.

3. **Missed KEEPALIVE**: Our tests explored how the protocol reacts if a bot fails to respond to the "KEEPALIVE" message from the server in a timely manner. The results were impressive, as the protocol recognized the issue and transitioned to the "ABORT" state, promptly disconnecting the problematic bot.

4. **Unreceived KEEPALIVE**: We assessed how the protocol behaves when a bot is expecting a "KEEPALIVE" message from the server but doesn't receive it. True to its robust design, the protocol quickly detected the communication breakdown, automatically entering the "ABORT" state and disconnecting the affected bot.

5. **End of Attack Reporting**: Another crucial aspect was testing a bot's ability to report the end of an attack as expected. In cases where a bot failed to do so, the protocol took immediate action, transitioning to the "ABORT" state to prevent any unintended continuation of the attack.

# Message Types
![image](https://github.com/EshedHere/BotNet/assets/140636322/c1dd9fbf-1c1c-42a1-a708-fa72ba64dc26)

# FSM
![image](https://github.com/EshedHere/BotNet/assets/140636322/4a13daf0-e94f-482a-b791-4ce463a2fa08)


