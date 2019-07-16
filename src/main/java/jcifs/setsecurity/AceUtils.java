package jcifs.setsecurity;

import jcifs.internal.dtyp.ACE;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.SID;

public class AceUtils {

	public static int encode( byte[] buf, int bi ,ACE ace) {
        return encode(buf,bi,null,ace);
    }
    
    static int encode( byte[] buf, int bi, Integer aceAccess ,ACE ace) {

        buf[bi++] = ace.isAllow() ? (byte)0x00 : (byte)0x01;
        buf[bi++] = (byte)ace.getFlags();

        int size = getACESize(ace);
        SMBUtil.writeInt2(size,buf,bi);
        bi+=2;

        SMBUtil.writeInt4(aceAccess != null ? aceAccess : ace.getAccessMask(),buf,bi);
        bi+=4;

        byte[] sidArr = SID.toByteArray(ace.getSID());
        SMBAdditionalUtils.writeByteArr(SID.toByteArray(ace.getSID()),buf,bi);
        bi+=sidArr.length;

        return size;
    }
    
    static public int getACESize(ACE ace){
        byte[] sidArr = SID.toByteArray(ace.getSID());
        return 1 + 1 + 2 + 4 + sidArr.length;
    }
}
