import spacy
import random
import requests
from datetime import datetime

class CyberSecurityChatbot:
    def __init__(self):
        # Load the language model
        self.nlp = spacy.load("en_core_web_sm")
        # Initialize conversation history and tips
        self.conversation_history = []
        self.tips = [
            "Be cautious of phishing scams and never click on suspicious links.",
            "Always use strong, unique passwords for each of your accounts.",
            "Enable two-factor authentication wherever possible.",
            "Keep your software and systems up to date to protect against vulnerabilities.",
            "Regularly back up your data to avoid loss in case of a cyber attack.",
            "Be mindful of sharing personal information online and use privacy settings on social media.",
        ]  
        self.introduction()

    def introduction(self):
        """ Introduces the chatbot and provides a greeting based on the time of day. """
        self.greet_during_day()
        # Print the welcome message
        print("Welcome to the CyberOps Chatbot! I'm here to help you with your queries related to cybersecurity, various hacking tools used by hackers,"
          " tips for maintaining a secure system, and privacy information.")
        
        print(f"Tip of the day: {self.get_random_tip()}")

    def greet_during_day(self):
        """ Provides a time-based greeting. """
        current_hour = datetime.now().hour
        if 5 <= current_hour < 12:
            print("Good morning!")
        elif 12 <= current_hour < 17:
            print("Good afternoon!")
        elif 17 <= current_hour < 21:
            print("Good evening!")
        else:
            print("Hello! It's quite late, but I'm here to help you with cybersecurity queries.")

    def get_random_tip(self):
        """ Returns a random cybersecurity tip. """
        return random.choice(self.tips)

    def fetch_wikipedia_summary(self, topic):
        """ Fetches a summary from Wikipedia for a given topic. """
        topic = topic.replace(" ", "_")  # Replace spaces with underscores for URL
        wikipedia_api_url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{topic}"
        try:
            response = requests.get(wikipedia_api_url)
            response.raise_for_status()
            data = response.json()
            return data.get('extract', 'No summary available.')
        except requests.RequestException as e:
            return f"Error fetching data from Wikipedia API: {e}"

    def generate_response(self, query):
        """ Generates a response based on the user's query. """
        query = query.lower()
        doc = self.nlp(query)
        response = ""
        if "malware" in query:
            if "types" in query:
                response = (
                    "Malware types include:\n"
                    "- **Virus**: Attaches itself to clean files and spreads to other files.\n"
                    "- **Worm**: Spreads without user action, exploiting vulnerabilities.\n"
                    "- **Trojan Horse**: Disguises itself as legitimate software but has malicious intent.\n"
                    "- **Ransomware**: Encrypts files and demands ransom for decryption.\n"
                    "- **Spyware**: Secretly monitors user activity to collect information.\n"
                    "- **Adware**: Displays unwanted advertisements, often in a browser.\n"
                    "- **Rootkit**: Gives unauthorized access to a system.\n"
                    "Remediations include keeping software updated, using antivirus software, avoiding suspicious links, and regularly backing up data."
                )
            else:
                response = (
                    "Malware is any software intentionally designed to cause damage to a computer, server, client, or computer network. For more information, you can read this [comprehensive guide](https://www.malwarebytes.com/malware)."
                )
        elif "hackers" in query or "ethical hacking" in query:
            if "types" in query:
                response = (
                    "Types of ethical hackers include:\n"
                    "- **White Hat Hacker**: Authorized hackers who use their skills for defensive purposes.\n"
                    "- **Black Hat Hacker**: Unethical hackers who exploit vulnerabilities for malicious purposes.\n"
                    "- **Gray Hat Hacker**: Hackers who may cross legal lines but don't have malicious intent.\n"
                    "- **Red Team Hackers**: Simulates real-world attacks to test an organization's defenses.\n"
                    "- **Blue Team Hackers**: Defends against attacks and strengthens security posture."
                )
            else:
                response = (
                    "Ethical hacking involves authorized attempts to gain unauthorized access to a system, data, or application to identify vulnerabilities. For further reading, check out this [ethical hacking overview](https://www.csoonline.com/article/3273577/what-is-ethical-hacking-types-and-tactics.html)."
                )
        elif "hacker groups" in query:
            response = (
                "Here are some well-known hacker groups and their locations:\n"
                "- **Anonymous**: A decentralized group of hacktivists with members globally.\n"
                "- **Lazarus Group**: Linked to North Korea, known for financially motivated attacks.\n"
                "- **Fancy Bear (APT28)**: A Russian group associated with cyber-espionage.\n"
                "- **Cozy Bear (APT29)**: Another Russian group involved in cyber-espionage.\n"
                "- **Equation Group**: Believed to be tied to the NSA in the United States.\n"
                "- **Syrian Electronic Army (SEA)**: A pro-government group in Syria.\n"
                "- **REvil (Sodinokibi)**: A ransomware group from Eastern Europe/Russia.\n"
                "- **Lizard Squad**: Known for DDoS attacks, with members in various countries.\n"
                "- **APT41 (Double Dragon)**: A Chinese group involved in cyber-espionage and financial crime."
            )
        elif "osi model" in query:
            response = self.fetch_wikipedia_summary("OSI_model")
            response += (
                "\n\nThe OSI model consists of the following seven layers:\n"
                "1. **Physical Layer**: Transmits raw bit stream over the physical medium.\n"
                "2. **Data Link Layer**: Handles error detection, correction, and frames.\n"
                "3. **Network Layer**: Manages packet forwarding including routing through different routers.\n"
                "4. **Transport Layer**: Provides reliable delivery of packets between hosts.\n"
                "5. **Session Layer**: Manages sessions between applications.\n"
                "6. **Presentation Layer**: Translates data between the application and network formats.\n"
                "7. **Application Layer**: Supports application and end-user processes.\n"
            )
        elif "tcp/ip model" in query or "tcp ip model" in query:
            response = self.fetch_wikipedia_summary("Internet_protocol_suite")
            response += (
                "\n\nThe TCP/IP model consists of the following four layers:\n"
                "1. **Application Layer**: Transmits application-specific data between applications.\n"
                "2. **Transport Layer**: Provides reliable, ordered, and error-checked delivery of data packets between applications.\n"
                "3. **Internet Layer**: Translates data packets between hosts on different networks.\n"
                "4. **Network Layer**: Manages packet routing and forwarding across networks."
            )
        elif "wireless network security" in query:
            response = self.fetch_wikipedia_summary("Wireless_security")
        elif "network attacks" in query or "remediation attacks" in query:
            if "types" in query:
                response = (
                    "Network attacks can take various forms, including:\n"
                    "- **Denial of Service (DoS)**: Overwhelms a network or service, making it unavailable to users.\n"
                    "- **Man-in-the-Middle (MitM)**: Intercepts communication between two parties without their knowledge.\n"
                    "- **Phishing**: Tricks users into revealing sensitive information by pretending to be a trustworthy entity.\n"
                    "- **Spoofing**: Fakes the identity of a device or user to gain unauthorized access.\n"
                    "- **SQL Injection**: Exploits vulnerabilities in a web application's database to execute malicious SQL commands.\n"
                )
            else:
                response = (
                    "Remediation strategies include:\n"
                    "- **Implementing strong network security measures** like firewalls and intrusion detection systems.\n"
                    "- **Regularly updating and patching** software to fix vulnerabilities.\n"
                    "- **Educating users** about phishing and social engineering tactics.\n"
                    "- **Using encryption** to secure data in transit and at rest."
                )
        elif "network tools" in query:
            response = (
                "Here are some commonly used network tools in cybersecurity:\n"
                "- **Nmap**: A network scanning tool used to discover hosts and services on a network.\n"
                "- **Wireshark**: A network protocol analyzer used to capture and inspect network traffic.\n"
                "- **Metasploit**: A penetration testing framework that helps find and exploit vulnerabilities.\n"
                "- **Nessus**: A vulnerability scanner used to identify vulnerabilities in systems and networks.\n"
                "- **Netcat**: A versatile networking tool used for network debugging and data transfer.\n"
                "- **Aircrack-ng**: A suite of tools used for assessing Wi-Fi network security.\n"
                "- **tcpdump**: A command-line packet analyzer tool used for capturing network traffic.\n"
                "- **John the Ripper**: A password-cracking tool used to identify weak passwords.\n"
                "- **Burp Suite**: A web vulnerability scanner used for security testing of web applications.\n"
                "- **Hydra**: A tool used for performing brute-force attacks on network services.\n"
            )
        elif "firewalls" in query:
            response = (
                "A firewall is a network security device that monitors and filters incoming and outgoing network traffic based on security policies. It acts as a barrier between a trusted network and an untrusted network, such as the internet. Firewalls can be hardware-based, software-based, or both, and they are a critical component in network security to protect against unauthorized access and threats.\n"
                "There are several types of firewalls, including:\n"
                "- **Packet-filtering Firewalls**: Inspect packets and allow or block them based on predefined rules.\n"
                "- **Stateful Inspection Firewalls**: Track the state of active connections and make decisions based on the context of traffic.\n"
                "- **Proxy Firewalls**: Act as intermediaries between users and the internet, filtering requests and responses.\n"
                "- **Next-Generation Firewalls (NGFW)**: Combine traditional firewall capabilities with advanced features like application awareness, intrusion prevention, and deep packet inspection."
            )
        elif "kali linux" in query:
                response = (
                "Kali Linux is a popular Linux distribution used for penetration testing, ethical hacking, and digital forensics. It comes pre-installed with a wide range of security tools, making it a go-to choice for security professionals and enthusiasts.\n"
                "To install Kali Linux, follow these steps:\n"
                "1. **Download the ISO**: Visit the official Kali Linux website and download the ISO image for your system.\n"
                "2. **Create a Bootable USB**: Use a tool like Rufus or Balena Etcher to create a bootable USB drive with the Kali Linux ISO.\n"
                "3. **Boot from USB**: Restart your computer and boot from the USB drive to start the Kali Linux installer.\n"
                "4. **Install Kali Linux**: Follow the on-screen instructions to install Kali Linux on your system.\n"
                "5. **Set Up Language and Location**: Follow the prompts to select your preferred language, location, and keyboard layout.\n"
                "6. **Configure Network and Hostname**: Set up your network configuration and hostname for the system.\n"
                "7. **Partition Disks**: Choose the partitioning method and allocate disk space for Kali Linux.\n"
                "8. **Install the Base System**: The installer will copy the necessary files and install the base system.\n"
                "9. **Set Up Users and Passwords**: Create a root password and, optionally, a regular user account.\n"
                "10. **Install GRUB Boot Loader**: Install the GRUB boot loader to the primary drive.\n"
                "11.**Complete Installation**: Once the installation is complete, restart your computer and boot into Kali Linux.\n"
                "- Kindly navigate to this link to install kali linux ISO file (https://www.kali.org/).\n"
                
                "Troubleshooting steps:\n"
                "- **Check hardware compatibility**: Make sure your hardware is compatible with Kali Linux.\n"
                "- **Boot Issues**: If Kali Linux does not boot from the USB, ensure the boot order is set correctly in the BIOS/UEFI settings.\n"
                "- **Partitioning Errors**: Double-check the disk partitioning step. Ensure you do not overwrite important data or partitions.\n"
                "- **Network Configuration**: If the network setup fails, try configuring the network manually or check the network hardware compatibility.\n"
                "- **GRUB Installation**: If GRUB fails to install, try reinstalling it using a live Kali Linux session or another Linux distribution.\n"
                "- **Freezing or Crashing**: If the installer freezes or crashes, check the installation media for errors or try a different USB drive.\n"
                "- **Verify ISO integrity**: Check the integrity of the ISO image you downloaded to ensure it is not corrupted.\n"
                "- **Update drivers**: Install the latest drivers for your hardware to avoid compatibility issues.\n"
                "- **Consult the community**: The Kali Linux community is active and can help you troubleshoot any issues you encounter."
            )


        elif "Parrot Security OS":
            response = (
            "   - **Description**: Parrot Security OS is a Debian-based Linux distribution focused on security, privacy, and development. It includes a full portable laboratory for security and digital forensics experts.\n"
            "   - **Installation Steps**:\n"
            "     1. Download the Parrot Security OS ISO from the official website.\n"
            "     2. Use a tool like Rufus to create a bootable USB drive.\n"
            "     3. Boot from the USB drive and select 'Install' from the menu.\n"
            "     4. Follow the on-screen instructions to install Parrot OS.\n"
            "   - **Download Link**: [Parrot Security OS](https://www.parrotsec.org/download/)\n"
            
            "   - **Troubleshooting Steps**:\n"
            "     - Ensure the USB drive is properly created and that your system is set to boot from USB.\n"
            "     - Check for hardware compatibility, particularly with network and graphic components.\n"
            "     - Update system repositories if installation issues arise.\n\n"
            )

        elif "BlackArch Linux" in query:
            response =(
            "   - **Description**: BlackArch Linux is an Arch Linux-based distribution designed for penetration testing and security research. It offers a vast repository of security tools.\n"
            "   - **Installation Steps**:\n"
            "     1. Download the BlackArch Linux ISO or install it on top of an existing Arch Linux installation.\n"
            "     2. Create a bootable USB or DVD from the ISO file.\n"
            "     3. Boot from the installation media and follow the installation guide.\n"
            "   - **Download Link**: [BlackArch Linux](https://blackarch.org/downloads.html)\n"
            
            "   - **Troubleshooting Steps**:\n"
            "     - Verify the downloaded ISO with checksums to prevent corrupted installations.\n"
            "     - Ensure proper disk partitioning to avoid data loss.\n"
            "     - Use the latest Arch Linux repositories to avoid outdated packages.\n\n"
            )

        elif "CAINE (Computer Aided Investigative Environment)" in query:
            response = (
            "   - **Description**: CAINE is an Ubuntu-based distribution designed for digital forensics, providing a wide range of forensic tools to investigate and analyze data.\n"
            "   - **Installation Steps**:\n"
            "     1. Download the CAINE ISO from the official website.\n"
            "     2. Use a tool like Etcher to create a bootable USB drive.\n"
            "     3. Boot from the USB drive and choose 'Install CAINE'.\n"
            "     4. Follow the on-screen prompts to complete the installation.\n"
            "   - **Download Link**: [CAINE](https://www.caine-live.net/)\n"
            
            "   - **Troubleshooting Steps**:\n"
            "     - Use 'nomodeset' if you encounter graphical issues during boot.\n"
            "     - Ensure all necessary drivers are installed post-installation.\n"
            "     - Check USB integrity if boot errors occur.\n\n"
            )

        elif "Fedora Security Spin" in query:
            response = (
            "   - **Description**: Fedora Security Spin is a Fedora Linux-based distribution that includes a set of open-source security tools for information security professionals and students.\n"
            "   - **Installation Steps**:\n"
            "     1. Download the Fedora Security Spin ISO from the official website.\n"
            "     2. Create a bootable USB using Fedora Media Writer.\n"
            "     3. Boot from the USB drive and select 'Install Fedora'.\n"
            "     4. Follow the guided installation steps.\n"
            "   - **Download Link**: [Fedora Security Spin](https://spins.fedoraproject.org/security/)\n"
            
            "   - **Troubleshooting Steps**:\n"
            "     - Disable Secure Boot in BIOS/UEFI if the system fails to boot.\n"
            "     - Verify the ISO checksum to ensure a proper download.\n"
            "     - Configure network settings and drivers after installation.\n\n"
            )

        elif "Qubes OS" in query:
            response = (
            "   - **Description**: Qubes OS is a security-focused desktop operating system that uses virtualization to isolate different tasks. It is designed for high-security environments.\n"
            "   - **Installation Steps**:\n"
            "     1. Download the Qubes OS ISO from the official website.\n"
            "     2. Create a bootable USB using a tool like Rufus.\n"
            "     3. Boot from the USB and follow the installation wizard.\n"
            "     4. Configure the system according to your security needs.\n"
            "   - **Download Link**: [Qubes OS](https://www.qubes-os.org/downloads/)\n"
            
            "   - **Troubleshooting Steps**:\n"
            "     - Ensure your hardware supports virtualization and UEFI.\n"
            "     - Enable VT-x and VT-d in BIOS/UEFI settings for Qubes OS.\n"
            "     - Use reliable installation media to avoid installation errors.\n"
            )
        elif "virtualbox" in query:
            response = (
                "To install Kali Linux on VirtualBox, follow these steps:\n\n"
                "1. **Download VirtualBox**: Go to the official VirtualBox website and download the installer for your OS.\n"
                "2. **Download Kali Linux ISO**: Download the Kali Linux ISO from the official website (https://www.kali.org/).\n"
                "3. **Create a New Virtual Machine**: Open VirtualBox and click 'New' to create a new VM. Set the name, type, and version (Linux, Debian 64-bit).\n"
                "4. **Configure Memory**: Allocate at least 2GB of RAM for the VM.\n"
                "5. **Create a Virtual Hard Disk**: Select 'Create a virtual hard disk now' and choose the VDI (VirtualBox Disk Image) format.\n"
                "6. **Set Hard Disk Storage**: Allocate at least 20GB of storage.\n"
                "7. **Attach Kali Linux ISO**: Go to 'Settings' > 'Storage', and attach the downloaded ISO under 'Controller: IDE'.\n"
                "8. **Start the VM**: Start the VM and follow the installation prompts inside the VM to install Kali Linux.\n"
                "9. **Set Up Network**: Configure the VM's network settings to connect to your local network.\n"
                "10. **Configure VirtualBox**: In the VM's settings, enable virtualization and enable USB 3.0 support.\n"
                "- Kindly navigate to this link to install the virtualbox (https://www.virtualbox.org/).\n"
            )
        elif "fedora" in query:
            response = (
                "To install Kali Linux on Fedora, you will set up a dual boot. Here are the steps:\n\n"
                "1. **Download Kali Linux ISO**: Obtain the ISO from the official Kali Linux website (https://www.kali.org/).\n"
                "2. **Create a Bootable USB Drive**: Use tools like Rufus to create a bootable USB drive with the Kali Linux ISO.\n"
                "3. **Shrink Fedora Partition**: Use Fedora's disk management tool to shrink an existing partition and free up space for Kali Linux.\n"
                "4. **Boot from USB**: Restart your system and boot from the USB drive.\n"
                "5. **Install Kali Linux**: Follow the installation steps to install Kali Linux on the newly freed space, alongside Fedora.\n"
                "6. **Set Up GRUB Bootloader**: Install the GRUB bootloader to manage the dual-boot setup.\n"
                "7. **Configure Network**: Connect the VM to your local network and configure network settings.\n"
                "- Kindly navigate to this site to install fedora workstation on your machine (https://fedoraproject.org/workstation/).\n"
            )
        elif "vmware" in query:
            response = (
                "To install Kali Linux on VMware, follow these steps:\n\n"
                "1. **Download VMware Workstation Player**: Go to the official VMware website and download the VMware Workstation Player for your OS.\n"
                "2. **Download Kali Linux ISO**: Download the Kali Linux ISO from the official website (https://www.kali.org/).\n"
                "3. **Create a New Virtual Machine**: Open VMware and select 'Create a New Virtual Machine'.\n"
                "4. **Select Installer Disk Image**: Choose 'Installer disc image file (iso)' and browse to the Kali Linux ISO you downloaded.\n"
                "5. **Select Guest Operating System**: Choose 'Linux' and 'Debian 10.x 64-bit'.\n"
                "6. **Configure VM Name and Location**: Set the name and location for your VM.\n"
                "7. **Allocate Disk Space**: Provide at least 20GB for the virtual disk.\n"
                "8. **Customize Hardware**: Allocate at least 2GB of RAM and configure network settings as needed.\n"
                "9. **Finish Setup and Power On**: Complete the setup and power on the VM to begin the installation of Kali Linux.\n"
                "- **Kindly visit this link to install Vmware (https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion)**.\n"
            )
        elif "security challenges faced by organizations" in query:
            response = (
                "Organizations today face numerous cybersecurity challenges, including:\n"
                "- **Phishing Attacks**: Deceptive attempts to obtain sensitive information by pretending to be a trustworthy entity.\n"
                "- **Ransomware**: Malware that encrypts data and demands a ransom for decryption.\n"
                "- **Insider Threats**: Threats posed by employees or contractors who have authorized access to systems.\n"
                "- **Advanced Persistent Threats (APTs)**: Prolonged and targeted attacks designed to steal data or disrupt operations.\n"
                "- **Data Breaches**: Unauthorized access to sensitive information, often resulting in significant financial and reputational damage.\n"
                "- **Compliance Requirements**: Meeting the growing number of regulatory requirements and industry standards.\n"
                "- **Lack of Cybersecurity Awareness**: Employees may not be aware of cybersecurity risks or best practices.\n"
                "- **Third-Party Risks**: Weak security practices of third-party vendors or partners can introduce vulnerabilities.\n"
                "- **Cloud Security**: Protecting data and applications stored in cloud environments from unauthorized access and data breaches.\n"
            )
        elif "elements of information security" in query or "information security elements" in query:
            response = (
                "- **Confidentiality**: Assurance of that the information is accessible only to those authorized to have access.\n"
                "- **Integrity**: The trustworthiness of data or resources in terms of preventing improper or unauthorized access.\n"
                "- **Availability**: Assurance that the systems responsible for delivering, storing, and processing information are accessible when required by the authorized users.\n"
                "- **Authenticity**: This refers to the characteristics of a communication, document or any data that ensures the quality of being genuine.\n"
                "- **Non-Repudiation**: A guarantee that the sender of a message cannot later deny having sent the message and that the recipient of the message cannot deny receiving the message.\n"
            )
        elif "motives behind information security attacks" in query:
            response = (
                "- A motive originates out of the notion that the target system stores or processes something valuable, and this leads to the threat of an attack on the system.\n"
                "- Here are some reasons behind why an attacker may be motivated to cause disruptions to informational security systems:\n"
                "- Stealing and manipulating sensitive data of users.\n"
                "- Creating fear and chaos by disrupting critical infrastructures.\n"
                "- Causing financial loss to the target.\n"
                "- Damaging the reputation of the target.\n"
            )
        elif "Classification of Attacks" in query:
            response = (
                "- **Passive Attacks**: This is a kind of an attack where the hacker does not tamper with the data but rather intercepts and monitors the flow of the data as well as the network traffic on the target system.\n"
                "- **Active Attack**: This is an attack where the attacker does tamper with the data in transit or disrupts the communication or services between the systems to bypass or break into secured systems.\n"
                "- **Close-in-Attack**: This attack is performed when the attacker appears to be in close physical proximity with the target system or network in order to gather, modify or disrupt access to information.\n"
                "- **Insider Attacks**: This involves using privileged access to violate rules or intentionally cause a threat to the organization's information or information systems.\n"
                "- **Distribution Attacks**: This Occur when attackers tamper with the hardware or software prior to installation. Attackers tamper with the hardware or software at its source or in transit.\n"
            )
        else:
            response = "I'm sorry, I don't have information on that topic. Can you ask about something else related to cybersecurity?"

        self.conversation_history.append(f"You: {query}")
        self.conversation_history.append(f"Chatbot: {response}")
        return response

    def display_conversation_history(self):
        """ Displays the conversation history. """
        print("Conversation History:")
        for entry in self.conversation_history:
            print(entry)

    def run(self):
        """ Starts the chatbot interaction loop. """
        print("Type 'exit' to end the conversation.")
        while True:
            user_input = input("You: ")
            if user_input.lower() == "exit":
                print("Goodbye!")
                break
            response = self.generate_response(user_input)
            print(f"Chatbot: {response}")

if __name__ == "__main__":
    chatbot = CyberSecurityChatbot()
    chatbot.run()
