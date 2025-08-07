package com.eren.chat;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class MainFrame extends JFrame {

    private JTextArea chatArea;
    private JTextField inputField;
    private JButton sendButton;
    private JList<String> onlineList;
    private DefaultListModel<String> listModel;

    private DatagramSocket broadcastSocket;
    private Thread broadcastListenerThread;
    private final int UDP_PORT = 50000;
    private final int GATEWAY_PORT = 50001; // private port

    // gateway nodelar
    private boolean isGatewayMode = false;
    private List<InetAddress> knownGatewayAddrs = new CopyOnWriteArrayList<>();
    private DatagramSocket gatewaySocket; 
    private Thread gatewayListenerThread;

    private String myNick = "";
    private long myJoinTime = 0L;
    private PublicKey myPublicKey;
    private PrivateKey myPrivateKey;
    private boolean isConnected = false;

    // lists
    private final ConcurrentMap<String, Instant> receivedIds = new ConcurrentHashMap<>();
    private ScheduledExecutorService prunerExecutor;
    private final Map<String, PublicKey> userPublicKeys = new ConcurrentHashMap<>();
    private final Map<String, InetAddress> userAddresses = new ConcurrentHashMap<>();
    private final Set<String> repliedToJoin = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final ConcurrentMap<String, TreeMap<Integer, String>> messageFragments = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Instant> fragmentTimestamps = new ConcurrentHashMap<>();
    // file
    private final Map<String, SecretKey> fileTransferKeys = new ConcurrentHashMap<>();
    private final Map<String, Object[]> filesPending= new ConcurrentHashMap<>();
    private final Map<String, ByteArrayOutputStream> incomingFiles = new ConcurrentHashMap<>();
    // priv msg
    private final Map<String, PrivateChatWindow> privWindows = new ConcurrentHashMap<>();
    private final Map<String, List<String>> privHistory = new ConcurrentHashMap<>();
    private final Set<String> privateNotifiedUsers = Collections.newSetFromMap(new ConcurrentHashMap<>());
    
    private final Set<String> b2uIds = Collections.synchronizedSet(new HashSet<>());  // broadcast to unicat
    private final Set<String> u2bIds = Collections.synchronizedSet(new HashSet<>());  // unicast to brdcast
    private final ScheduledExecutorService cacheCleaner = Executors.newSingleThreadScheduledExecutor();                                 

    public MainFrame() {
        loadGatewayList();
        setupPacketPruner();
        initUI();
    }

    private void initUI() {
        setTitle("Anonymous Chat Client");
        setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                if (isConnected) {
                    disconnect();
                }
                if (prunerExecutor != null) prunerExecutor.shutdownNow();
                System.exit(0);
            }
        });
        setSize(400, 300);
        setLocationRelativeTo(null);

        JMenuBar menuBar = new JMenuBar();
        JMenu fileMenu = new JMenu("File");
        JMenuItem generateKeysItem = new JMenuItem("Generate Keys");
        generateKeysItem.addActionListener(e -> {
            try {
            	if (this.myPublicKey != null) {
                    JOptionPane.showMessageDialog(this, "You have required keys.");
                } else {
                    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                    keyGen.initialize(2048);
                    KeyPair pair = keyGen.generateKeyPair();
                    
                    this.myPublicKey = pair.getPublic();
                    this.myPrivateKey = pair.getPrivate();
                    JOptionPane.showMessageDialog(this, "Keys are created.");
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Key creation error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        });
        fileMenu.add(generateKeysItem);

        JMenuItem connectItem = new JMenuItem("Connect to network");
        connectItem.addActionListener(e -> {
            if (!isConnected) connect();
            else JOptionPane.showMessageDialog(this, "You are already connected.");
        });
        fileMenu.add(connectItem);

        JMenuItem disconnectItem = new JMenuItem("Disconnect");
        disconnectItem.addActionListener(e -> {
            if (isConnected) disconnect();
            else JOptionPane.showMessageDialog(this, "You are not connected.");
        });
        fileMenu.add(disconnectItem);
        fileMenu.addSeparator();
        JMenuItem exitItem = new JMenuItem("Exit");
        exitItem.addActionListener(e -> {
            if (isConnected) disconnect();
            System.exit(0);
        });
        fileMenu.add(exitItem);
        menuBar.add(fileMenu);
        setJMenuBar(menuBar);

        JMenu modeMenu = new JMenu("Mode");
        JRadioButtonMenuItem clientItem = new JRadioButtonMenuItem("Client Mode", true);
        JRadioButtonMenuItem gatewayItem = new JRadioButtonMenuItem("Gateway Mode");
        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(clientItem);
        modeGroup.add(gatewayItem);
        clientItem.addActionListener(e -> isGatewayMode = false);
        gatewayItem.addActionListener(e -> isGatewayMode = true);
        modeMenu.add(clientItem);
        modeMenu.add(gatewayItem);
        menuBar.add(modeMenu);

        JMenu helpMenu = new JMenu("Help");
        JMenuItem aboutItem = new JMenuItem("About");
        aboutItem.addActionListener(e -> {
            JOptionPane.showMessageDialog(this,
                    "This application was developed by Eren Utku Karataş",
                    "About This App",
                    JOptionPane.INFORMATION_MESSAGE);
        });
        helpMenu.add(aboutItem);
        menuBar.add(helpMenu);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setDividerLocation(280);
        chatArea = new JTextArea();
        chatArea.setEditable(false);
        chatArea.setLineWrap(true);
        chatArea.setWrapStyleWord(true);
        splitPane.setLeftComponent(new JScrollPane(chatArea));

        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.setBorder(BorderFactory.createTitledBorder("Online Users"));
        listModel = new DefaultListModel<>();
        onlineList = new JList<>(listModel);
        rightPanel.add(new JScrollPane(onlineList), BorderLayout.CENTER);
        splitPane.setRightComponent(rightPanel);

        onlineList.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e) && onlineList.getSelectedIndex() != -1) {
                    String displayName = onlineList.getSelectedValue();
                    String realNick = getRealNick(displayName);
                    if (realNick.equalsIgnoreCase(myNick)) return;
                    JPopupMenu menu = new JPopupMenu();
                    JMenuItem pmItem = new JMenuItem("Private Message");
                    pmItem.addActionListener(ev -> openPrivChat(realNick));
                    menu.add(pmItem);
                    JMenuItem sendFileItem = new JMenuItem("Send File");
                    sendFileItem.addActionListener(ev -> prepareFile(realNick));
                    menu.add(sendFileItem);
                    menu.show(onlineList, e.getX(), e.getY());
                }
            }
        });

        JPanel bottomPanel = new JPanel(new BorderLayout(5, 5));
        bottomPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        inputField = new JTextField();
        sendButton = new JButton("Send");
        sendButton.setEnabled(false);
        bottomPanel.add(inputField, BorderLayout.CENTER);
        bottomPanel.add(sendButton, BorderLayout.EAST);
        sendButton.addActionListener(e -> sendMessage());
        inputField.addActionListener(e -> sendMessage());

        setLayout(new BorderLayout());
        add(splitPane, BorderLayout.CENTER);
        add(bottomPanel, BorderLayout.SOUTH);
    }
    
    
    //gateway list
    private void loadGatewayList() {
        knownGatewayAddrs.clear();
        Path path = Paths.get("gateways.txt");
        if (!Files.exists(path)) {
            System.out.println("gateways.txt is not found.");
            return;
        }
        try {
            List<String> lines = Files.readAllLines(path);
            for (String line : lines) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue; //yorum varsa geç
                try {
                    knownGatewayAddrs.add(InetAddress.getByName(line));
                } catch (Exception ex) {
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void setupPacketPruner() {
        prunerExecutor = Executors.newSingleThreadScheduledExecutor();
        prunerExecutor.scheduleAtFixedRate(() -> {
            Instant now = Instant.now();
            receivedIds.entrySet().removeIf(entry -> entry.getValue().isBefore(now.minusSeconds(120)));
            
            // Yarım kalmış büyük mesajları temizle
            fragmentTimestamps.entrySet().removeIf(entry -> {
                if (entry.getValue().isBefore(now.minusSeconds(60))) {
                    messageFragments.remove(entry.getKey());                   
                    return true;
                }
                return false;
            });

        }, 30, 30, TimeUnit.SECONDS);
    }
    
     // iface bulunmayınca linux çalışmıyo
    private boolean waitForNetworkInterfaces(long timeoutMillis) throws InterruptedException {
        long startTime = System.currentTimeMillis();
        while (System.currentTimeMillis() - startTime < timeoutMillis) {
            try {
                Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
                while (interfaces.hasMoreElements()) {
                    NetworkInterface netIf = interfaces.nextElement();
                    if (netIf.isUp() && !netIf.isLoopback()) {
                        for (InterfaceAddress addr : netIf.getInterfaceAddresses()) {
                            if (addr.getBroadcast() != null) {
                                return true; 
                            }
                        }
                    }
                }
            } catch (SocketException e) {
                System.err.println("error");
            }          
            Thread.sleep(500);
        }
        return false; // zamanaşımı
    }
    
    
    private void connect() {
        if (isConnected) return;
        if (this.myPublicKey == null) {
            JOptionPane.showMessageDialog(this, "First File -> Generate Keys", "Keys are missing", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String nickname = JOptionPane.showInputDialog(this, "Nickname:", "Connect", JOptionPane.PLAIN_MESSAGE);
        if (nickname == null || nickname.trim().isEmpty()) return;
        myNick = nickname.trim();

        try {
        	if (!waitForNetworkInterfaces(10000)) {
                JOptionPane.showMessageDialog(this, "Network not found. Connection failed.", "Network Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            InetAddress local = null;
            try {
                local = getLocalIP();
            } 
            catch (IOException e) {
            
            }
            broadcastSocket = new DatagramSocket(null);
            broadcastSocket.setReuseAddress(true);

            if (local != null) {
            	broadcastSocket.bind(new InetSocketAddress(local,UDP_PORT)); //internete ulaşan
            } else {
            	broadcastSocket.bind(new InetSocketAddress(UDP_PORT)); //hostonly ağ
            }
            
            startBroadcastListener(broadcastSocket);
            if (isGatewayMode) { //private portu dinle
                gatewaySocket = new DatagramSocket(GATEWAY_PORT);
                gatewayListenerThread = new Thread(() -> {
                    byte[] buf = new byte[65535];

                    while (!gatewaySocket.isClosed()) {
                        try {
                            DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                            gatewaySocket.receive(pkt);
                            handleGatewayPacket(pkt);  
                        } catch (IOException e) {
                            if (!gatewaySocket.isClosed()) System.err.println("error");
                        }
                    }
                }, "GatewayListener");
                gatewayListenerThread.start();
            }

            myJoinTime = System.currentTimeMillis();
            String keyBase64 = Base64.getEncoder().encodeToString(myPublicKey.getEncoded());
            String joinId = UUID.randomUUID().toString();
            String payload = keyBase64 + "," + myJoinTime;
            String joinMsg = "JOIN|" + joinId + "|" + myNick + "|" + payload;
            broadcastUdp(joinMsg);

            userPublicKeys.put(myNick, myPublicKey);
            listModel.addElement(myNick + " (Me)");
            chatArea.append("Connected as '" + myNick + "'.\n");
            sendButton.setEnabled(true);
            isConnected = true;
        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(this, "Connection Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            if (broadcastSocket != null) broadcastSocket.close();
        }
    }

    private void disconnect() {
        if (!isConnected) return;
        try {
            String quitId = UUID.randomUUID().toString();
            String quitMsg = "QUIT|" + quitId + "|" + myNick;
            broadcastUdp(quitMsg);       
            Thread.sleep(500); //direkt kapatınca disconnect olabilsin
        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            if (broadcastListenerThread != null) broadcastListenerThread.interrupt();
            if (broadcastSocket != null) broadcastSocket.close();

            userPublicKeys.clear();
            userAddresses.clear();
            repliedToJoin.clear();
            listModel.clear();
            privWindows.values().forEach(Window::dispose);
            privWindows.clear();
            privHistory.clear();
            privateNotifiedUsers.clear();
            filesPending.clear();
            incomingFiles.clear();
            fileTransferKeys.clear();
            
            if (gatewayListenerThread != null) gatewayListenerThread.interrupt();
            if (gatewaySocket != null) gatewaySocket.close();

            SwingUtilities.invokeLater(() -> {
                chatArea.setText("");
                chatArea.append("Disconnected from network.\n");
                sendButton.setEnabled(false);
            });
            isConnected = false;
            System.out.println("Disconnected.");
        }
    }
    private InetAddress getLocalIP() throws IOException {
        try (DatagramSocket s = new DatagramSocket()) {
            s.connect(InetAddress.getByName("8.8.8.8"), 80);
            return s.getLocalAddress();
        }catch (Exception e) {
            return null;
        }
    }
    

    private void broadcastUdp(String msg) {
        try {
            InetAddress broadcastAddr = null;
            NetworkInterface outIf   = null;

            InetAddress local = null;
            try {
                local = getLocalIP();
            } catch (IOException ignored) {
                
            }

            // tüm iplere değil sadece 192.168.1.107ye at
            if (local != null) {
                outIf = NetworkInterface.getByInetAddress(local);
                for (InterfaceAddress ia : outIf.getInterfaceAddresses()) {
                    if (ia.getAddress().equals(local) && ia.getBroadcast() != null) {
                        broadcastAddr = ia.getBroadcast();
                        break;
                    }
                }
            }
            
            if (broadcastAddr == null) {
                Enumeration<NetworkInterface> ifs = NetworkInterface.getNetworkInterfaces();
                while (ifs.hasMoreElements() && broadcastAddr == null) {
                    NetworkInterface netIf = ifs.nextElement();
                    if (!netIf.isUp() || netIf.isLoopback()) continue;
                    for (InterfaceAddress ia : netIf.getInterfaceAddresses()) {
                        InetAddress bc   = ia.getBroadcast();
                        InetAddress addr = ia.getAddress();
                        if (bc != null && addr.isSiteLocalAddress()) {
                            outIf         = netIf;
                            broadcastAddr = bc;
                            break;
                        }
                    }
                }
            }

            if (broadcastAddr != null && outIf != null) {
                sendSpoofedPacket(
                    broadcastAddr.getHostAddress(),
                    UDP_PORT,
                    msg,
                    outIf.getDisplayName()
                );
            } else {
                System.err.println("Broadcast yapmadı");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //ip ve mac spoof için python kısmı
    private void sendSpoofedPacket(String targetIp, int port, String data, String iface) {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            String pythonCmd = os.contains("win") ? "python" : "python3"; //linuxta python3
            String scriptPath = os.contains("win") ? "spoofer.py" : "/home/eren/spoofer/spoofer.py";

            List<String> command = new ArrayList<>();
            if (!os.contains("win")) {
                command.add("sudo");
            }
            command.add(pythonCmd);
            command.add(scriptPath);
            command.add("--target-ip");
            command.add(targetIp);
            command.add("--target-port");
            command.add(String.valueOf(port));
            command.add("--data");
            command.add(data);
            if (iface != null && !iface.isEmpty()) {
                command.add("--iface");
                command.add(iface);
            }

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            new Thread(() -> {
                try (var reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        System.out.println("python: " + line);
                    }
                } catch (IOException e) {  }
            }).start();
        } catch (Exception e) {           
            System.err.println("error");
        }
    }
    
    private void sendMessage() {
        String msgText = inputField.getText().trim();
        if (msgText.isEmpty() || !isConnected) return;
        final String finalMsgText = msgText;
        SwingUtilities.invokeLater(() -> {
            inputField.setText("");
            chatArea.append("Me: " + finalMsgText + "\n");
        });

        if (userPublicKeys.size() <= 1) return;

        new Thread(() -> {
            try {
                String msgId = UUID.randomUUID().toString();
                final int RSA_CHUNK_SIZE = 200;
                byte[] msgBytes = finalMsgText.getBytes(StandardCharsets.UTF_8);

                if (msgBytes.length <= RSA_CHUNK_SIZE) {
                    StringBuilder payloadBuilder = new StringBuilder();
                    userPublicKeys.forEach((nick, pubKey) -> {
                        if (!nick.equalsIgnoreCase(myNick)) {
                            try {
                                byte[] cipherBytes = CryptoUtils.encryptWithPublicKey(finalMsgText, pubKey);
                                String base64Cipher = Base64.getEncoder().encodeToString(cipherBytes);
                                if (payloadBuilder.length() > 0) payloadBuilder.append(";");
                                payloadBuilder.append(nick).append(";").append(base64Cipher);
                            } catch (Exception e) { System.err.println("error"); }
                        }
                    });
                    String messagePacket = "MSG|" + msgId + "|" + myNick + "|" + payloadBuilder.toString();
                    broadcastUdp(messagePacket);
                } else {
                    List<byte[]> plainChunks = new ArrayList<>();
                    for (int from = 0; from < msgBytes.length; from += RSA_CHUNK_SIZE) {
                        int to = Math.min(from + RSA_CHUNK_SIZE, msgBytes.length);
                        plainChunks.add(Arrays.copyOfRange(msgBytes, from, to));
                    }
                    int totalChunks = plainChunks.size();
                    for (int i = 0; i < totalChunks; i++) {
                        String chunkStr = new String(plainChunks.get(i), StandardCharsets.UTF_8);
                        StringBuilder payloadBuilder = new StringBuilder();
                        userPublicKeys.forEach((nick, pubKey) -> {
                            if (!nick.equalsIgnoreCase(myNick)) {
                                try {
                                    byte[] cipherBytes = CryptoUtils.encryptWithPublicKey(chunkStr, pubKey);
                                    String base64Cipher = Base64.getEncoder().encodeToString(cipherBytes);
                                    if (payloadBuilder.length() > 0) payloadBuilder.append(";");
                                    payloadBuilder.append(nick).append(";").append(base64Cipher);
                                } catch (Exception e) { e.printStackTrace(); }
                            }
                        });
                        String messagePacket = "MSG-PART|" + msgId + "|" + myNick + "|" + i + "|" + totalChunks + "|" + payloadBuilder.toString();
                        broadcastUdp(messagePacket);
                        Thread.sleep(30);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }

    private void sendPrivMsg(String recipientNick, String msgText) {
        new Thread(() -> {
            try {
                PublicKey pubK = userPublicKeys.get(recipientNick);
                if (pubK == null) return;
                byte[] cipherBytes = CryptoUtils.encryptWithPublicKey(msgText, pubK);
                String base64Cipher = Base64.getEncoder().encodeToString(cipherBytes);
                String msgId = UUID.randomUUID().toString();
                String fullMsg = "PMSG|" + msgId + "|" + myNick + "|" + recipientNick + "|" + base64Cipher;
                broadcastUdp(fullMsg);
            } catch (Exception e) {
               
            }
        }).start();
    }

    private void prepareFile(String recipientNick) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select a file to send to " + recipientNick);
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            new Thread(() -> {
                File selectedFile = fileChooser.getSelectedFile();
                PublicKey recipientPubKey = userPublicKeys.get(recipientNick);
                if (recipientPubKey == null) return;
                try {
                    SecretKey sessionKey = CryptoUtils.generateAesKey();
                    byte[] encryptedSessionKey = CryptoUtils.encryptWithPublicKey(Base64.getEncoder().encodeToString(sessionKey.getEncoded()), recipientPubKey);
                    String base64EncryptedKey = Base64.getEncoder().encodeToString(encryptedSessionKey);
                    String msgId = UUID.randomUUID().toString();
                    filesPending.put(msgId, new Object[]{selectedFile, sessionKey});
                    String offerPacket = String.join("|", "FILE-OFFER", msgId, myNick, recipientNick, selectedFile.getName(), String.valueOf(selectedFile.length()), base64EncryptedKey);
                    SwingUtilities.invokeLater(() -> chatArea.append("Sending file offer for '" + selectedFile.getName() + "' to " + recipientNick + "...\n"));
                    broadcastUdp(offerPacket);
                } catch (Exception e) {
                    System.err.println("error");
                }
            }).start();
        }
    }


    private void sendFile(String msgId, String recipientNick) {
        new Thread(() -> {
            try {
                Object[] transferInfo = filesPending.get(msgId);
                if (transferInfo == null) return;
                File fileToSend = (File) transferInfo[0];
                SecretKey sessionKey = (SecretKey) transferInfo[1];
                
                final int CHUNK_SIZE = 512;
                byte[] buffer = new byte[CHUNK_SIZE];

                try (FileInputStream fis = new FileInputStream(fileToSend)) {
                    int bytesRead;
                    int chunkIndex = 0;
                    while ((bytesRead = fis.read(buffer)) != -1) {
                        byte[] actualChunk = Arrays.copyOf(buffer, bytesRead);
                        byte[] encryptedChunk = CryptoUtils.encryptWithAes(actualChunk, sessionKey);
                        String base64Chunk = Base64.getEncoder().encodeToString(encryptedChunk);
                        
                        String chunkPacket = String.join("|", "FILE-CHUNK", msgId, myNick, recipientNick, String.valueOf(chunkIndex), base64Chunk);
                        
                        broadcastUdp(chunkPacket);
                        
                        Thread.sleep(35);                         
                        chunkIndex++;
                    }
                }
                

                Thread.sleep(100); // EOF arada kaynamasın
                String eofPacket = String.join("|", "FILE-EOF", msgId, myNick, recipientNick, fileToSend.getName());
                broadcastUdp(eofPacket);
                SwingUtilities.invokeLater(() -> chatArea.append("File '" + fileToSend.getName() + "' sent successfully.\n"));
                
            } catch (Exception e) {
                System.err.println("error");
            } finally {
                filesPending.remove(msgId);
            }
        }).start();
    }
    
    
    private void startBroadcastListener(DatagramSocket socket) {
        broadcastListenerThread = new Thread(() -> {
            byte[] buf = new byte[65535];
            while (socket != null && !socket.isClosed()) {
                try {
                    DatagramPacket packet = new DatagramPacket(buf, buf.length);
                    socket.receive(packet);
                    handleBroadcastPacket(packet);
                } catch (IOException e) {
                    if (!socket.isClosed()) System.err.println("Listener error: " + e.getMessage());
                }
            }
        }, "BroadcastListener");
        broadcastListenerThread.start();
    }
    
    //unicasti broadcast
    private void handleGatewayPacket(DatagramPacket packet) throws IOException {
        String data = new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8);
        String[] parts = data.split("\\|", 8);
        if (parts.length < 3) return;

        String type = parts[0];
        String msgId = parts[1];

        String uniqueKey;
        if (type.equals("MSG-PART") && parts.length >= 5) {
            uniqueKey = msgId + "-" + parts[3] + "-" + type;
        } else if (type.equals("FILE-CHUNK") && parts.length >= 6) {
            uniqueKey = msgId + "-" + parts[4] + "-" + type;
        } else {
            uniqueKey = msgId + "-" + type;
        }

        if (!u2bIds.add(uniqueKey)) return;

        cacheCleaner.schedule(() -> u2bIds.remove(uniqueKey), 2, TimeUnit.MINUTES);
        broadcastUdp(data);
    }
    
    private void handleBroadcastPacket(DatagramPacket packet) {
        try {
            String data = new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8);
            String[] parts = data.split("\\|", 8);
            if (parts.length < 3) return;

            String type = parts[0];
            String msgId = parts[1];
            String senderNick = parts[2];

            switch (type) {
                case "JOIN":
                    if (receivedIds.putIfAbsent(msgId, Instant.now()) != null) break;
                    if (senderNick.equalsIgnoreCase(myNick)) break;
                    if (parts.length < 4) break;
                    String[] joinPayloadParts = parts[3].split(",", 2);
                    if (joinPayloadParts.length < 2) break;
                    if (!userPublicKeys.containsKey(senderNick)) {
                        String keyBase64 = joinPayloadParts[0];
                        PublicKey newKey = CryptoUtils.loadPublicKeyFromBytes(Base64.getDecoder().decode(keyBase64));
                        userPublicKeys.put(senderNick, newKey);
                        userAddresses.put(senderNick, packet.getAddress());
                        SwingUtilities.invokeLater(() -> {
                            listModel.addElement(senderNick);
                            chatArea.append(senderNick + " joined the chat.\n");
                        });
                    }
                    if (!repliedToJoin.contains(senderNick)) {
                        String myKeyB64 = Base64.getEncoder().encodeToString(myPublicKey.getEncoded());
                        String replyJoinId = UUID.randomUUID().toString();
                        String replyPayload = myKeyB64 + "," + myJoinTime;
                        String replyMsg = "JOIN|" + replyJoinId + "|" + myNick + "|" + replyPayload;
                        broadcastUdp(replyMsg);
                        repliedToJoin.add(senderNick);
                    }
                    break;
                case "QUIT":
                    if (receivedIds.putIfAbsent(msgId, Instant.now()) != null) break;
                    if (senderNick.equalsIgnoreCase(myNick)) break;
                    userPublicKeys.remove(senderNick);
                    userAddresses.remove(senderNick);
                    SwingUtilities.invokeLater(() -> {
                        for (int i = 0; i < listModel.size(); i++) {
                            if (getRealNick(listModel.getElementAt(i)).equalsIgnoreCase(senderNick)) {
                                listModel.removeElementAt(i);
                                break;
                            }
                        }
                        chatArea.append(senderNick + " left the chat.\n");
                    });
                    repliedToJoin.remove(senderNick);
                    break;
                case "MSG":
                    if (receivedIds.putIfAbsent(msgId, Instant.now()) != null) break;
                    if (senderNick.equalsIgnoreCase(myNick)) break;
                    if (parts.length < 4) break;
                    String[] msgBlocks = parts[3].split(";");
                    for (int i = 0; i < msgBlocks.length; i += 2) {
                        if (msgBlocks[i].equalsIgnoreCase(myNick)) {
                            byte[] cipherBytes = Base64.getDecoder().decode(msgBlocks[i + 1]);
                            String plainMsg = CryptoUtils.decryptWithPrivateKey(cipherBytes, myPrivateKey);
                            SwingUtilities.invokeLater(() -> chatArea.append(senderNick + ": " + plainMsg + "\n"));
                            break;
                        }
                    }
                    break;
                case "PMSG":
                    {
                        if (parts.length < 5) break;
                        String recipientNick = parts[3];
                        if (recipientNick.equalsIgnoreCase(myNick)) {
                            if (receivedIds.putIfAbsent(msgId, Instant.now()) != null) break;
                            try {
                                String payload = parts[4];
                                String plainMsg = CryptoUtils.decryptWithPrivateKey(Base64.getDecoder().decode(payload), myPrivateKey);
                                privHistory.computeIfAbsent(senderNick, k -> new ArrayList < > ()).add(senderNick + ": " + plainMsg);
                                SwingUtilities.invokeLater(() -> {
                                    if (privWindows.containsKey(senderNick)) {
                                        privWindows.get(senderNick).receiveMessage(senderNick, plainMsg);
                                    } else {
                                        addNotification(senderNick);
                                    }
                                });
                            } catch (Exception e) {
                                System.err.println("error");
                            }
                        }
                        break;
                    }
                case "MSG-PART":
                    if (senderNick.equalsIgnoreCase(myNick)) break;
                    if (parts.length < 6) break;
                    int partNo = Integer.parseInt(parts[3]);
                    if (receivedIds.putIfAbsent(msgId + "-" + partNo, Instant.now()) != null) break;
                    int totalParts = Integer.parseInt(parts[4]);
                    String[] partBlocks = parts[5].split(";");
                    for (int i = 0; i < partBlocks.length; i += 2) {
                        if (partBlocks[i].equalsIgnoreCase(myNick)) {
                            String plainChunkStr = CryptoUtils.decryptWithPrivateKey(Base64.getDecoder().decode(partBlocks[i + 1]), myPrivateKey);
                            TreeMap < Integer, String > fragments = messageFragments.computeIfAbsent(msgId, k -> new TreeMap < > ());
                            fragments.put(partNo, plainChunkStr);
                            if (fragments.size() == totalParts) {
                                StringBuilder fullMsg = new StringBuilder();
                                fragments.values().forEach(fullMsg::append);
                                messageFragments.remove(msgId);
                                SwingUtilities.invokeLater(() -> chatArea.append(senderNick + ": " + fullMsg.toString() + "\n"));
                            }
                            break;
                        }
                    }
                    break;
                case "FILE-OFFER":
                    if (parts.length < 7) break;
                    String offerRecipient = parts[3];
                    if (offerRecipient.equalsIgnoreCase(myNick)) {
                        if (receivedIds.putIfAbsent(msgId, Instant.now()) != null) break;
                        String fileName = parts[4];
                        long fileSize = Long.parseLong(parts[5]);
                        byte[] encryptedKeyBytes = Base64.getDecoder().decode(parts[6]);
                        String keyStr = CryptoUtils.decryptWithPrivateKey(encryptedKeyBytes, myPrivateKey);
                        SecretKey sessionKey = new SecretKeySpec(Base64.getDecoder().decode(keyStr), "AES");
                        String message = String.format("%s wants to send you '%s' (%d KB). Accept?", senderNick, fileName, fileSize / 1024);
                        int response = JOptionPane.showConfirmDialog(this, message, "File Transfer Request", JOptionPane.YES_NO_OPTION);
                        String responseType = (response == JOptionPane.YES_OPTION) ? "FILE-ACCEPT" : "FILE-REJECT";
                        if (responseType.equals("FILE-ACCEPT")) fileTransferKeys.put(msgId, sessionKey);
                        broadcastUdp(String.join("|", responseType, msgId, myNick, senderNick));
                    }
                    break;
                case "FILE-ACCEPT":
                    if (parts.length < 4) break;
                    if (parts[3].equalsIgnoreCase(myNick)) {
                        if (receivedIds.putIfAbsent(msgId + "-ACCEPT", Instant.now()) != null) break;
                        SwingUtilities.invokeLater(() -> chatArea.append(senderNick + " accepted. Starting file transfer...\n"));
                        sendFile(msgId, senderNick);
                    }
                    break;
                case "FILE-REJECT":
                    if (parts.length < 4) break;
                    if (parts[3].equalsIgnoreCase(myNick)) {
                        if (receivedIds.putIfAbsent(msgId + "-REJECT", Instant.now()) != null) break;
                        filesPending.remove(msgId);
                        SwingUtilities.invokeLater(() -> chatArea.append(senderNick + " rejected the file transfer.\n"));
                    }
                    break;
                case "FILE-CHUNK":
                    if (parts.length < 6) break;
                    if (parts[3].equalsIgnoreCase(myNick)) {
                        String partNum = parts[4];
                        if (receivedIds.putIfAbsent(msgId + "-CHUNK-" + partNum, Instant.now()) != null) break;
                        SecretKey sessionKey = fileTransferKeys.get(msgId);
                        if (sessionKey == null) break;
                        byte[] decryptedChunk = CryptoUtils.decryptWithAes(Base64.getDecoder().decode(parts[5]), sessionKey);
                        incomingFiles.computeIfAbsent(msgId, k -> new ByteArrayOutputStream()).write(decryptedChunk);
                    }
                    break;
                case "FILE-EOF":
                    if (parts.length < 5) break;
                    if (parts[3].equalsIgnoreCase(myNick)) {
                        if (receivedIds.putIfAbsent(msgId + "-EOF", Instant.now()) != null) break;
                        final ByteArrayOutputStream bos = incomingFiles.remove(msgId);
                        fileTransferKeys.remove(msgId);
                        if (bos == null) {
                            SwingUtilities.invokeLater(() -> chatArea.append("File transfer from " + senderNick + " failed. (No data received)\n"));
                            break;
                        }
                        final String fileName = parts[4];
                        SwingUtilities.invokeLater(() -> {
                            JFileChooser fileChooser = new JFileChooser();
                            fileChooser.setSelectedFile(new File(fileName));
                            if (fileChooser.showSaveDialog(MainFrame.this) == JFileChooser.APPROVE_OPTION) {
                                try (FileOutputStream fos = new FileOutputStream(fileChooser.getSelectedFile())) {
                                    fos.write(bos.toByteArray());
                                    JOptionPane.showMessageDialog(MainFrame.this, "File received!", "Success", JOptionPane.INFORMATION_MESSAGE);
                                } catch (IOException e) {
                                    e.printStackTrace();
                                }
                            }
                        });
                    }
                    break;
            }

            if (isGatewayMode) {
                String uniqueKey;
                if (type.equals("MSG-PART") && parts.length >= 5) {
                    uniqueKey = msgId + "-" + parts[3] + "-" + type; 
                } else if (type.equals("FILE-CHUNK") && parts.length >= 6) {
                    uniqueKey = msgId + "-" + parts[4] + "-" + type; 
                } else {
                    uniqueKey = msgId + "-" + type; 
                }

                if (b2uIds.add(uniqueKey)) {
                    cacheCleaner.schedule(() -> b2uIds.remove(uniqueKey), 2, TimeUnit.MINUTES);
                    for (InetAddress gw : knownGatewayAddrs) {
                        if (!gw.equals(gatewaySocket.getLocalAddress())) {
                            DatagramPacket up = new DatagramPacket(packet.getData(), 0, packet.getLength(), gw, GATEWAY_PORT);
                            gatewaySocket.send(up);
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("error");
        }
    }
    
    private String getRealNick(String displayName) {
        if (displayName == null) return "";
        String nick = displayName.trim();
        if (nick.endsWith(" (Me)")) nick = nick.substring(0, nick.length() - 5).trim();
        if (nick.endsWith(" 🔔")) nick = nick.substring(0, nick.length() - 2).trim();
        return nick;
    }

    private void addNotification(String userNick) {
        if (privateNotifiedUsers.add(userNick)) {
            SwingUtilities.invokeLater(() -> {
                for (int i = 0; i < listModel.size(); i++) {
                    if (getRealNick(listModel.getElementAt(i)).equalsIgnoreCase(userNick)) {
                        listModel.setElementAt(userNick + " 🔔", i);
                        break;
                    }
                }
            });
        }
    }

    private void removeNotification(String userNick) {
        if (privateNotifiedUsers.remove(userNick)) {
            SwingUtilities.invokeLater(() -> {
                for (int i = 0; i < listModel.size(); i++) {
                    if (getRealNick(listModel.getElementAt(i)).equalsIgnoreCase(userNick)) {
                        listModel.setElementAt(userNick, i);
                        break;
                    }
                }
            });
        }
    }

    private PrivateChatWindow openPrivChat(String userNick) {
        removeNotification(userNick);
        PrivateChatWindow window = privWindows.computeIfAbsent(userNick, k -> new PrivateChatWindow(this, userNick));
        window.toFront();
        window.requestFocus();
        List<String> history = privHistory.get(userNick);
        if (history != null) {
            window.privateChatArea.setText("");
            history.forEach(line -> window.privateChatArea.append(line + "\n"));
        }
        return window;
    }
    
    private class PrivateChatWindow extends JFrame {
        private final String chatWith;
        private final JTextArea privateChatArea;

        public PrivateChatWindow(JFrame parent, String chatWith) {
            this.chatWith = chatWith;
            setTitle("Private Chat with " + chatWith);
            setSize(200, 250);
            setLocationRelativeTo(parent);

            privateChatArea = new JTextArea();
            privateChatArea.setEditable(false);
            privateChatArea.setLineWrap(true);
            privateChatArea.setWrapStyleWord(true);
            add(new JScrollPane(privateChatArea), BorderLayout.CENTER);

            JPanel bottomPanel = new JPanel(new BorderLayout(5, 5));
            JTextField privateInputField = new JTextField();
            JButton privateSendButton = new JButton("Send");
            
            bottomPanel.add(privateInputField, BorderLayout.CENTER);
            bottomPanel.add(privateSendButton, BorderLayout.EAST);
            add(bottomPanel, BorderLayout.SOUTH);

            Runnable sendMessageAction = () -> {
                String text = privateInputField.getText().trim();
                if (!text.isEmpty()) {
                    receiveMessage("Me", text);
                    privHistory.computeIfAbsent(chatWith, k -> new ArrayList<>()).add("Me: " + text);
                    sendPrivMsg(chatWith, text);
                    privateInputField.setText("");
                }
            };

            privateInputField.addActionListener(e -> sendMessageAction.run());
            privateSendButton.addActionListener(e -> sendMessageAction.run());

            addWindowListener(new WindowAdapter() {
                @Override
                public void windowClosing(WindowEvent e) {
                    privWindows.remove(chatWith);
                }
            });
            setVisible(true);
        }
        public void receiveMessage(String sender, String msg) {
            privateChatArea.append(sender + ": " + msg + "\n");
        }
    }
    
    
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new MainFrame().setVisible(true));
    }
}