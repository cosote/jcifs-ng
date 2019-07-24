package jcifs.smb;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.internal.dtyp.ACE;
import jcifs.internal.smb2.create.Smb2CreateRequest;
import jcifs.setsecurity.Smb2SetACLRequest;
import jcifs.setsecurity.Smb2SetOwnerRequest;
import jcifs.setsecurity.Smb2SetSecurityInfoRequest;

public class SmbFileSecurity extends SmbFile {
	
	private SmbFileHandleImpl fileHandle;
	private byte[] file_id;
	
	public SmbFileSecurity (String url, CIFSContext context) throws MalformedURLException,SmbException,CIFSException
	{
		 super(new URL(null, url, context.getUrlHandler()), context);
		 this.fileHandle = openUnshared(O_RDWR, WRITE_DAC | WRITE_OWNER,DEFAULT_SHARING, 0, isDirectory() ? 1 : 0);
		 this.file_id = getOpenedFileId(this.fileHandle);
	}
	
	private byte[] getOpenedFileId(SmbFileHandleImpl f) throws SmbException
	{
		int fid = f.getFid();
        ByteBuffer bb = ByteBuffer.allocate(16);    
        byte[] file_id_byte_arr= bb.order(ByteOrder.LITTLE_ENDIAN).putInt(fid).array();
        return file_id_byte_arr;
	}
    
    private void sendSecurityRequest(Smb2SetSecurityInfoRequest req) throws SmbException,CIFSException
    {
        SmbTreeHandleImpl h = ensureTreeConnected();
        //if the request is not made with the withOpen function then you will get a 0xC0000128 error (file closed)
        withOpen(h, Smb2CreateRequest.FILE_OPEN, WRITE_DAC | WRITE_OWNER, DEFAULT_SHARING, req);
    }
    
    public void setFileACL(ACE[] aceArray) throws SmbException,CIFSException
    {
        Smb2SetACLRequest req = new Smb2SetACLRequest(this.fileHandle.getTree().getConfig(),this.file_id,aceArray);
        sendSecurityRequest(req);
    }
    
    public void setFileOwner(SID newOwner) throws SmbException,CIFSException
    {
         Smb2SetOwnerRequest req = new Smb2SetOwnerRequest(this.fileHandle.getTree().getConfig(),this.file_id,newOwner);
         sendSecurityRequest(req);        
    }
}
