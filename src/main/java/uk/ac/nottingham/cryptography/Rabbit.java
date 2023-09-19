package uk.ac.nottingham.cryptography;



import static java.lang.Integer.rotateLeft;

public class Rabbit implements RabbitCipher {
    int[] X;
    int[] C;
    int[] masterX;
    int[] masterC;
    int[] G;
    byte[] S;
    int[] A = {
            0x4D34D34D, 0xD34D34D3,
            0x34D34D34, 0x4D34D34D,
            0xD34D34D3, 0x34D34D34,
            0x4D34D34D, 0xD34D34D3
    };
    int b;
    int masterB;


    @Override
    public void initialiseCipher(byte[] key) {
        X = new int[8];
        C = new int[8];
        masterX = new int[8];
        masterC = new int[8];
        G = new int[8];
        S = new byte[16];
        b = 0;
        masterB = 0;
        A = new int[]{
                0x4D34D34D, 0xD34D34D3,
                0x34D34D34, 0x4D34D34D,
                0xD34D34D3, 0x34D34D34,
                0x4D34D34D, 0xD34D34D3
        };

        int[] k = new int[8];

        for (int i = 0; i < 8; i++) {

            k[i] = (twoBytesToInt(key[((2 * i) + 1)], key[(2 * i)]));
        }
        for (int i = 0; i < 8; i++) {

            if (i % 2 == 0){ //even
                X[i] = twoIntTo32bit(k[(i + 1) % 8], k[i]);
                C[i] = twoIntTo32bit(k[(i + 4) % 8], k[(i + 5) % 8]);
            }
            else { //odd
                X[i] = twoIntTo32bit(k[(i + 5) % 8], k[(i + 4) % 8]);
                C[i] = twoIntTo32bit(k[i], k[(i + 1) % 8]);
            }
        }
        nextState();
        nextState();
        nextState();
        nextState();

        for (int i = 0; i < 8; i++) {
            C[i] = C[i] ^ X[(i+4) % 8];
        }
        System.arraycopy(X,0,masterX,0,8);
        System.arraycopy(C,0,masterC,0,8);
        masterB = b;


    }

    @Override
    public void initialiseIV(byte[] iv) {
        if (iv != null){
            byte temp[] = new byte[8];
            for (int i = 0; i < 8; i++) {
                temp[i] = iv[7-i];
            }
            System.arraycopy(masterX,0,X,0,8);
            System.arraycopy(masterC,0,C,0,8);
            b = masterB;
            iv = temp;
            C[0] = C[0] ^ (twoIntTo32bit(twoBytesToInt(iv[4], iv[5]),twoBytesToInt(iv[6], iv[7])));
            C[1] = C[1] ^ (twoIntTo32bit(twoBytesToInt(iv[0], iv[1]),twoBytesToInt(iv[4], iv[5])));
            C[2] = C[2] ^ (twoIntTo32bit(twoBytesToInt(iv[0], iv[1]),twoBytesToInt(iv[2], iv[3])));
            C[3] = C[3] ^ (twoIntTo32bit(twoBytesToInt(iv[2], iv[3]),twoBytesToInt(iv[6], iv[7])));
            C[4] = C[4] ^ (twoIntTo32bit(twoBytesToInt(iv[4], iv[5]),twoBytesToInt(iv[6], iv[7])));
            C[5] = C[5] ^ (twoIntTo32bit(twoBytesToInt(iv[0], iv[1]),twoBytesToInt(iv[4], iv[5])));
            C[6] = C[6] ^ (twoIntTo32bit(twoBytesToInt(iv[0], iv[1]),twoBytesToInt(iv[2], iv[3])));
            C[7] = C[7] ^ (twoIntTo32bit(twoBytesToInt(iv[2], iv[3]),twoBytesToInt(iv[6], iv[7])));

            nextState();
            nextState();
            nextState();
            nextState();
        }
    }


    @Override
    public final void counterUpdate() {
        for (int i = 0; i < 8; i++) {
            long temp = ((C[i]& 0xFFFFFFFFL) + (A[i]& 0xFFFFFFFFL) + b) ;
            b = (int) (temp >>> 32);

            C[i] = (int)(temp & 0xFFFFFFFFL);
        }
    }

    @Override
    public final void nextState() {
        counterUpdate();
        for (int i = 0; i < 8; i++) {
            G[i] = g(X[i], C[i]);
        }
        X[0] =  ((G[0] + rotateLeft(G[7], 16 ) + rotateLeft(G[6], 16)) );
        X[1] =  ((G[1] + rotateLeft(G[0], 8 ) + (G[7])) );
        X[2] =  ((G[2] + rotateLeft(G[1], 16 ) + rotateLeft(G[0], 16)) );
        X[3] =  ((G[3] + rotateLeft(G[2], 8 ) + (G[1])) );
        X[4] =  ((G[4] + rotateLeft(G[3], 16 ) + rotateLeft(G[2], 16)) );
        X[5] =  ((G[5] + rotateLeft(G[4], 8 ) + (G[3])) );
        X[6] =  ((G[6] + rotateLeft(G[5], 16 ) + rotateLeft(G[4], 16)) );
        X[7] =  ((G[7] + rotateLeft(G[6], 8 ) + (G[5])));

    }

    public void updateBlock(){

        nextState();
        S[0] = (byte)((LS16of32(X[0]) ^ MS16of32(X[5])) & 0xFF);
        S[1] = (byte)((LS16of32(X[0]) ^ MS16of32(X[5])) >>> 8);
        S[2] = (byte)((MS16of32(X[0]) ^ LS16of32(X[3])) & 0xFF);
        S[3] = (byte)((MS16of32(X[0]) ^ LS16of32(X[3])) >>> 8);
        S[4] = (byte)((LS16of32(X[2]) ^ MS16of32(X[7])) & 0xFF);
        S[5] = (byte)((LS16of32(X[2]) ^ MS16of32(X[7])) >>> 8);
        S[6] = (byte)((MS16of32(X[2]) ^ LS16of32(X[5])) & 0xFF);
        S[7] = (byte)((MS16of32(X[2]) ^ LS16of32(X[5])) >>> 8);
        S[8] = (byte)((LS16of32(X[4]) ^ MS16of32(X[1])) & 0xFF);
        S[9] = (byte)((LS16of32(X[4]) ^ MS16of32(X[1])) >>> 8);
        S[10] = (byte)((MS16of32(X[4]) ^ LS16of32(X[7])) & 0xFF);
        S[11] = (byte)((MS16of32(X[4]) ^ LS16of32(X[7])) >>> 8);
        S[12] = (byte)((LS16of32(X[6]) ^ MS16of32(X[3])) & 0xFF);
        S[13] = (byte)((LS16of32(X[6]) ^ MS16of32(X[3])) >>> 8);
        S[14] = (byte)((MS16of32(X[6]) ^ LS16of32(X[1])) & 0xFF);
        S[15] = (byte)((MS16of32(X[6]) ^ LS16of32(X[1])) >>> 8);


    }

    @Override
    public void encrypt(byte[] block) {
        // Add your code here.
        updateBlock();
        for (int i = 0; i < block.length; i++) {
            block[i] ^= S[i];
        }
    }

    @Override
    public void encryptMessage(byte[] iv, byte[] message) {
        initialiseIV(iv);
        int blocks = (message.length - 1) / 16 + 1;
        int remainder = message.length % 16;
        if (blocks == 1 & remainder == 0){
            encrypt(message);
            return;
        }
        for (int i = 0; i < blocks-1; i++) {
            byte[] process = new byte[16];
            System.arraycopy(message, i*16,process,0,16);
            encrypt(process);
            System.arraycopy(process,0,message,i*16,16);
        }
        if (remainder == 0){
            byte[] process = new byte[16];
            System.arraycopy(message, (blocks-1)*16,process,0,16);
            encrypt(process);
            System.arraycopy(process,0,message,(blocks-1)*16,16);
        }

        byte[] process = new byte[remainder];
        System.arraycopy(message, (blocks-1)*16,process,0,remainder);
        encrypt(process);
        System.arraycopy(process,0,message,(blocks-1)*16,remainder);
    }

    @Override
    public void decrypt(byte[] block) {
        encrypt(block);
    }

    @Override
    public void decryptMessage(byte[] iv, byte[] message) {
        encryptMessage(iv,message);
    }

    @Override
    public String getStateString(StringOutputFormatting formatting) {
        StringBuilder str = new StringBuilder();
        switch (formatting){
            case PLAIN -> {
                for (int i = 0; i < 8; i++) {
                    for (int j = 0; j < 8 - Integer.toHexString(X[i]).length(); j++) {
                        str.append("0");
                    }
                    str.append(String.format(Integer.toHexString(X[i]), 255)).append(" ");
                }
                for (int i = 0; i < 8; i++) {
                    for (int j = 0; j < 8 - Integer.toHexString(C[i]).length(); j++) {
                        str.append("0");
                    }
                    str.append(String.format(Integer.toHexString(C[i]), 255)).append(" ");
                }
                str.append(Integer.toHexString(b));
                return str.toString().toUpperCase();
            }
            case FANCY -> {
                str.append("b = " + b + "\n");
                for (int i = 0; i < 4; i++) {
                    str.append("X" + i + " = " + hex(X[i]) + ", " );
                }
                str.setLength(str.length() - 1);
                str.append("\n");
                for (int i = 0; i < 4; i++) {
                    str.append("X" + (i+4) + " = " + hex(X[i+4]) + ", " );
                }
                str.setLength(str.length() - 1);
                str.append("\n");
                for (int i = 0; i < 4; i++) {
                    str.append("C" + i + " = " + hex(C[i]) + ", " );
                }
                str.setLength(str.length() - 1);
                str.append("\n");
                for (int i = 0; i < 3; i++) {
                    str.append("C" + (i+4) + " = " + hex(C[i+4]) + ", " );
                }

                str.append("C" + (7) + " = " + hex(C[7]));


                return str.toString();
            }
        }
        return str.toString();
    }

    //Helper Functions
    private int twoBytesToInt(byte msByte, byte lsByte){
        return ((msByte & 0xff) << 8) | (lsByte & 0xff);
    }
    private int twoIntTo32bit(int msByte, int lsByte){
        return ((msByte & 0xffff) << 16) | (lsByte & 0xffff);
    }
    private String hex(int a){
        String s = "0x";
        for (int j = 0; j < 8 - Integer.toHexString(a).length(); j++) {
            s = s + "0";
        }
        return (s + (String.format(Integer.toHexString(a), 255)).toUpperCase());
    }
    private int g(int u, int v){
        long square = u + v & 0xFFFFFFFFL;
        square *= square;
        return (int)(square ^ square >>> 32);
    }

    private int MS16of32 (int a){
        return a >>> 16;
    }
    private int LS16of32 (int a){
        return a & 0xffff;
    }

}
