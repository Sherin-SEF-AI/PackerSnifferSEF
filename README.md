# PackerSnifferSEF
Python GUI application for packet sniffer
# Packet Sniffer Application

## Overview
The Packet Sniffer Application is a graphical user interface (GUI) tool built with Python's Tkinter library. It allows users to monitor network traffic, log packet details, export logs, and visualize packet statistics. The application is designed to be user-friendly and includes features such as filtering, searching, and a dark mode toggle.

## Features
- **Start and Stop Sniffing**: Easily start and stop packet sniffing through the GUI.
- **Packet Filtering**: Filter packets based on specified criteria.
- **Interface Selection**: Choose the network interface to sniff packets from.
- **Protocol Selection**: Filter packets by protocol (TCP, UDP, ICMP, All).
- **Packet Logs**: View real-time packet logs in a text area.
- **Export Logs**: Export packet logs to a text file or CSV file.
- **Save and Load Configuration**: Save and load configuration settings (filter, interface, protocol).
- **Search Packets**: Search for specific packets within the logs.
- **Packet Statistics**: View real-time statistics of packet counts for different protocols.
- **Dark Mode**: Toggle dark mode for better visibility in low-light environments.

## Requirements
- Python 3.6 or later
- Required Python libraries:
  - tkinter
  - scapy
  - matplotlib

## Installation

1. **Clone the Repository**:
    ```sh
    git clone https://github.com/yourusername/packet-sniffer-app.git
    cd packet-sniffer-app
    ```

2. **Install Dependencies**:
    ```sh
    pip install -r requirements.txt
    ```

    If `requirements.txt` is not available, manually install the required libraries:
    ```sh
    pip install tk scapy matplotlib
    ```

## Usage

1. **Run the Application**:
    ```sh
    python packetsniffer.py
    ```

2. **Start Sniffing**:
    - Click on `File` -> `Start Sniffing`.
    - Specify filter criteria, network interface, and protocol.

3. **Stop Sniffing**:
    - Click on `File` -> `Stop Sniffing`.

4. **Export Logs**:
    - Click on `File` -> `Export Logs` to save logs to a text file.
    - Click on `File` -> `Export to CSV` to save logs to a CSV file.

5. **Save and Load Configuration**:
    - Click on `File` -> `Save Configuration` to save current settings.
    - Click on `File` -> `Load Configuration` to load previously saved settings.

6. **Search Packets**:
    - Enter a search term in the `Search` field and press Enter to search logs.

7. **Toggle Dark Mode**:
    - Click on `File` -> `Toggle Dark Mode` to switch between light and dark modes.



## Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

## License
This project is licensed under the MIT License.

## Acknowledgements
- [Scapy](https://scapy.net/) - Used for packet sniffing.
- [Tkinter](https://docs.python.org/3/library/tkinter.html) - Used for GUI development.
- [Matplotlib](https://matplotlib.org/) - Used for plotting packet statistics.
