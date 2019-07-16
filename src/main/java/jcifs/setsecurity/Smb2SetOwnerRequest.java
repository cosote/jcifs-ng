package jcifs.setsecurity;

import jcifs.Configuration;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.SID;

public class Smb2SetOwnerRequest extends Smb2SetSecurityInfoRequest{
	
	private SID newOwner;
    
	public Smb2SetOwnerRequest(Configuration config, byte[] fileId, SID newOwner)
	{
		super(config,fileId,SET_OWNER_INFORMATION);
		this.newOwner = newOwner;
	}
	
   //check https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d - for info about the DACL structure
    protected int writeDACL(byte[] dst, int dstIndex) {
    	int start = dstIndex;

        // Revision
        dst[dstIndex++] = (byte) 0x01;

        // Sbz1
        dst[dstIndex++] = (byte) 0x00; // Sbz1

        // Control
        SMBUtil.writeInt2(SET_OWNER_CONTROL_FLAGS, dst, dstIndex);
        dstIndex += 2;

        //-------- writting offsets --------

        //offset owner
        int OwnerOffsetIndex = dstIndex;
        dstIndex +=4;

        //offset group
        SMBUtil.writeInt4(NO_OFFSET, dst, dstIndex);
        dstIndex += 4;

        //offset Sacl
        SMBUtil.writeInt4(NO_OFFSET, dst, dstIndex);
        dstIndex += 4;
        
        //offset DACL
        SMBUtil. writeInt4(NO_OFFSET, dst, dstIndex);
        dstIndex += 4;
        
        //----------- writing the owner--------
        
        SMBUtil.writeInt4(dstIndex-start, dst, OwnerOffsetIndex);//set the Owner Offset
        System.arraycopy(this.newOwner.toByteArray(), 0, dst, dstIndex, this.newOwner.toByteArray().length);
        dstIndex += this.newOwner.toByteArray().length;
        
        return dstIndex - start;

    }

}
