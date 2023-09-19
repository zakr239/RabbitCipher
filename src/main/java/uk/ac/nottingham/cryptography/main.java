package uk.ac.nottingham.cryptography;

import java.util.ServiceLoader;

public class main {
    private final RabbitCipher cipher = ServiceLoader.load(RabbitCipher.class).findFirst().orElseThrow();
    public static void main(String[] args) {
        Rabbit cipher = new Rabbit();

        //r.initialiseCipher(new byte[] {(byte) 0x91, (byte)0x28, (byte)0x13, (byte)0x29, (byte)0x2E, (byte) 0xED, (byte)0x36, (byte) 0xFE, (byte)0x3B, (byte) 0xFC, (byte)0x62, (byte) 0xF1, (byte) 0xDC, (byte)0x51, (byte) 0xC3, (byte) 0xAC});
        //r.initialiseCipher(new byte[] { 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0 });
        //r.initialiseCipher(new byte[]{(byte)0xAC,(byte)0xC3,0x51,(byte)0xDC,(byte)0xF1,0x62,(byte)0xFC,0x3B,(byte)0xFE,0x36, (byte)0x3D, 0x2E, 0x29, 0x13, 0x28, (byte)0x91});
        //r.initialiseCipher(new byte[16]);
        //r.test();

        cipher.initialiseCipher(new byte[] { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 });
        cipher.initialiseIV(new byte[] { (byte)0xFF, (byte)0xFE,(byte)0xFD,(byte)0xFC,(byte)0xFB,(byte)0xFA,(byte)0xEF,(byte)0xEE });


        byte[] plaintext = hexStringToByteArray("7D 03 B5 70 37 49 64 C4 7D 14 D7 02 22 91 38 B9 81 98 53 ED B5 13 15 AF 7D 86 52 A5 1A 97 78 40 63 AA 3A 6E 2C 39 52 54 74 7E AB CE A7 66 55 21 A1 A7 10 02 38 53 7E E1 9B AA F7 7C E2 9A 63 C2");
        cipher.encryptMessage(new byte[] { (byte)0xFF, (byte)0xFE,(byte)0xFD,(byte)0xFC,(byte)0xFB,(byte)0xFA,(byte)0xEF,(byte)0xEE }, plaintext);
        System.out.println(plaintext);
        //r.initialiseIV(new byte[] { (byte)0xFA, 0x3E, 0x32, (byte)0xCD, (byte)0xA4, 0x02, (byte)0xFE, 0x01});
        //r.initialiseIV(new byte[] { (byte) 0x59, 0x7E, (byte)0x26, (byte)0xC1, (byte)0x75, (byte)0xF5, 0x73, (byte)0xC3});
        //r.initialiseIV(new byte[] { (byte)0xC3, 0x73, (byte)0xF5, 0x75, (byte)0xC1, 0x26, 0x7E, 0x59});

        //System.out.println(r.getStateString(RabbitCipher.StringOutputFormatting.PLAIN));

    }
    public static byte[] hexStringToByteArray(String s) {
        s = s.replace(" ", "");
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[(i / 2)] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}

