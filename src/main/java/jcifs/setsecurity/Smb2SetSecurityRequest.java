package jcifs.setsecurity;

//for more information about the flags and variable values check https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee9614c4-be54-4a3c-98f1-769a7032a0e4

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.dtyp.ACE;
import jcifs.internal.dtyp.SecurityDescriptor;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.SID;

public class Smb2SetSecurityRequest extends ServerMessageBlock2Request<Smb2SetSecurityInfoResponse>{
	
	protected final static long NO_OFFSET = 0l;
	protected final static long DACL_OFFSET = 20l;//DACL_OFFSET  = 2 (revision) + 2 (control) + 4*4 (4*offset)  =  20 bytes
	protected final static long SET_DACL_CONTROL_FLAGS = 0x9407;//todo: explain the flags
	
	
	//check for message structure -  https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee9614c4-be54-4a3c-98f1-769a7032a0e4
	private byte[] fileId;
    private byte infoType =(byte)0x03; //SMB2_0_INFO_SECURITY
    private byte fileInfoClass =(byte)0x00; //for setting security this field must be 0
    private int additionalInformation=(byte) 0x00000005; //set the DACLS and owner
    private SecurityDescriptor newDescriptor;
    private int descriptorSize;
    private Configuration config;
    private SID newOwner;
    

    /**
     * @param config
     * @param fileId
     */
    public Smb2SetSecurityRequest (Configuration config, byte[] fileId, SecurityDescriptor newDescriptor, SID newOwner ) {
        super(config, SMB2_SET_INFO);
        this.fileId = fileId;
        this.newDescriptor = newDescriptor;
        this.config = config;
        this.newOwner = newOwner;
    }
    
    
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
    	//https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee9614c4-be54-4a3c-98f1-769a7032a0e4 - information about the request message structure
        int start = dstIndex;
        //write 33 in the first two bytes, the number 33 is mandatory to use this type of request
        SMBUtil.writeInt2(33, dst, dstIndex);
        dst[ dstIndex + 2 ] = this.infoType;
        dst[ dstIndex + 3 ] = this.fileInfoClass;
        dstIndex += 4;

        int bufferLengthOffset = dstIndex;
        dstIndex += 4;
        int bufferOffsetOffset = dstIndex;
        dstIndex += 4;

        SMBUtil.writeInt4(this.additionalInformation, dst, dstIndex);
        dstIndex += 4;

        //write the fileID 
        System.arraycopy(this.fileId, 0, dst, dstIndex, 16);
        dstIndex += 16;

        //write the buffer offset (the length from the begining till the information to be set)
        SMBUtil.writeInt2(dstIndex - getHeaderStart(), dst, bufferOffsetOffset);
        
        //here we write the security information 
        int len = writeDACL(dst,dstIndex); //call the function which writes the dacl
        dstIndex += len;
        //write the length of the security information
        SMBUtil.writeInt4(len, dst, bufferLengthOffset);
        
        /* only for debugging purposes, the structure of the message
        int j=1;
        for(int i=start;i<dstIndex;i++)
        {
        	System.out.println(j+".  "+String.format("%8s", Integer.toBinaryString(dst[i] & 0xFF)).replace(' ', '0'));
        	j++;
        }
        */
        
        return dstIndex - start;
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

        //offset owner
        int OwnerOffsetIndex = dstIndex;
        dstIndex +=4;
//        SMBUtil.writeInt4(NO_OFFSET, dst, dstIndex);
//        dstIndex += 4;

        //offset group
        SMBUtil.writeInt4(NO_OFFSET, dst, dstIndex);
        dstIndex += 4;

        //offset Sacl
        SMBUtil.writeInt4(NO_OFFSET, dst, dstIndex);
        dstIndex += 4;
        
        //DACL_OFFSET  = 2 (revision) + 2 (control) + 4*4 (4*offset)  =  20 bytes
        int DaclOffsetIndex = dstIndex;
        SMBUtil. writeInt4(DACL_OFFSET, dst, dstIndex);
        dstIndex += 4;
        
        //----------- writing the owner--------
        
        SMBUtil.writeInt4(dstIndex-start, dst, OwnerOffsetIndex);//set the Owner Offset
        System.arraycopy(this.newOwner.toByteArray(), 0, dst, dstIndex, this.newOwner.toByteArray().length);
        dstIndex += this.newOwner.toByteArray().length;
        System.out.println("The offset of the owner info is "+(dstIndex-getHeaderStart()));
        
        //----------- writing the Dcls --------

        //Revision
        
        SMBUtil.writeInt4(dstIndex-start,dst,DaclOffsetIndex);
        dst[dstIndex++] = (byte) 0x02;
        dst[dstIndex++] = (byte) 0x00;

        int acesBlockSize = 1 + 1 + 2 + 4;//revision (2) + size (2) + numOfACEs(4)
        for (ACE ace : newDescriptor.getAces()) {
            acesBlockSize += AceUtils.getACESize(ace);
        }

        SMBUtil.writeInt2(acesBlockSize, dst, dstIndex);
        dstIndex += 2;

        SMBUtil.writeInt4(newDescriptor.getAces().length, dst, dstIndex);
        dstIndex += 4;

        for (ACE ace : newDescriptor.getAces()) {
            int size;
            size = AceUtils.encode(dst, dstIndex, ace);
            dstIndex += size;
        }
        
        this.descriptorSize = dstIndex-start; //this is needed in the size method of the request
        return dstIndex - start;

    }


    public int size () {
        return size8(Smb2Constants.SMB2_HEADER_LENGTH + 32 + this.descriptorSize);
    }


	@Override
	protected Smb2SetSecurityInfoResponse createResponse(CIFSContext tc, ServerMessageBlock2Request<Smb2SetSecurityInfoResponse> req) {
		// TODO Auto-generated method stub
		return new Smb2SetSecurityInfoResponse(this.config);
	}


	@Override
	protected int readBytesWireFormat(byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
		// TODO Auto-generated method stub
		return 0;
	}

}
