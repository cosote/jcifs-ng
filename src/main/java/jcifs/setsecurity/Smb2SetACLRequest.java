package jcifs.setsecurity;

import jcifs.Configuration;
import jcifs.internal.dtyp.ACE;
import jcifs.internal.util.SMBUtil;

public class Smb2SetACLRequest extends Smb2SetSecurityInfoRequest{
	
	private ACE[] aceArray;
    
	public Smb2SetACLRequest(Configuration config, byte[] fileId, ACE[] aceArray)
	{
		super(config,fileId,SET_DACL_INFORMATION);
		this.aceArray = aceArray;
	}
	
   //check https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d - for info about the DACL structure
    protected int writeDACL(byte[] dst, int dstIndex) {
        int start = dstIndex;

        // Revision
        dst[dstIndex++] = (byte) 0x01;

        // Sbz1
        dst[dstIndex++] = (byte) 0x00; // Sbz1

        // Control
        SMBUtil.writeInt2(SET_DACL_CONTROL_FLAGS, dst, dstIndex);
        dstIndex += 2;

        //-------- writting offsets --------

        SMBUtil.writeInt4(NO_OFFSET, dst, dstIndex);
        dstIndex += 4;

        //offset group
        SMBUtil.writeInt4(NO_OFFSET, dst, dstIndex);
        dstIndex += 4;

        //offset Sacl
        SMBUtil.writeInt4(NO_OFFSET, dst, dstIndex);
        dstIndex += 4;
        
        //DACL_OFFSET  = 2 (revision) + 2 (control) + 4*4 (4*offset)  =  20 bytes
        int DaclOffsetIndex = dstIndex;
        SMBUtil.writeInt4(DACL_OFFSET, dst, dstIndex);
        dstIndex += 4;
           
        SMBUtil.writeInt4(dstIndex-start,dst,DaclOffsetIndex);
        dst[dstIndex++] = (byte) 0x02;
        dst[dstIndex++] = (byte) 0x00;

        int acesBlockSize = 1 + 1 + 2 + 4;//revision (2) + size (2) + numOfACEs(4)
        for (ACE ace : this.aceArray) {
            acesBlockSize += AceUtils.getACESize(ace);
        }

        SMBUtil.writeInt2(acesBlockSize, dst, dstIndex);
        dstIndex += 2;

        SMBUtil.writeInt4(this.aceArray.length, dst, dstIndex);
        dstIndex += 4;

        for (ACE ace : this.aceArray) {
            int size;
            size = AceUtils.encode(dst, dstIndex,ace);
            dstIndex += size;
        }
        return dstIndex - start;

    }

}
