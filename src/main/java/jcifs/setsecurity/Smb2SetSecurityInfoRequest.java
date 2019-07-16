package jcifs.setsecurity;


//for more information about the flags and variable values check https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee9614c4-be54-4a3c-98f1-769a7032a0e4

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;

abstract public class Smb2SetSecurityInfoRequest extends ServerMessageBlock2Request<Smb2SetSecurityInfoResponse>{
	
	protected final static long NO_OFFSET = 0l;
	protected final static long DACL_OFFSET = 20l;//DACL_OFFSET  = 2 (revision) + 2 (control) + 4*4 (4*offset)  =  20 bytes
	protected final static long SET_DACL_CONTROL_FLAGS = 0x9407;//todo: explain the flags
	protected final static long SET_OWNER_CONTROL_FLAGS = 0x940B;
	protected final static int SET_OWNER_INFORMATION = 0x00000001;
	protected final static int SET_DACL_INFORMATION =  0x00000004;
	
	
	//check for message structure -  https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee9614c4-be54-4a3c-98f1-769a7032a0e4
	private byte[] fileId;
	private byte infoType =(byte)0x03; //SMB2_0_INFO_SECURITY
	private byte fileInfoClass =(byte)0x00; //for setting security this field must be 0
	private int additionalInformation; //set the DACLS and owner
	private int descriptorSize;
	private Configuration config;
  

  /**
   * @param config
   * @param fileId
   */
	public Smb2SetSecurityInfoRequest (Configuration config, byte[] fileId, int additionalInformation) {
      super(config, SMB2_SET_INFO);
      this.fileId = fileId;
      this.config = config;
      this.additionalInformation = additionalInformation;
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
		this.descriptorSize = len;
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
	abstract protected int writeDACL(byte[] dst, int dstIndex);


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
