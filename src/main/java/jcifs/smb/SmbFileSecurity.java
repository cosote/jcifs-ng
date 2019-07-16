package jcifs.smb;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import jcifs.CIFSContext;
import jcifs.internal.dtyp.ACE;
import jcifs.internal.smb2.create.Smb2CreateRequest;
import jcifs.setsecurity.Smb2SetACLRequest;
import jcifs.setsecurity.Smb2SetOwnerRequest;

public class SmbFileSecurity extends SmbFile {
	
	public SmbFileSecurity (String url, CIFSContext context) throws MalformedURLException
	{
		 super(new URL(null, url, context.getUrlHandler()), context);
	}
	
	private byte[] getOpenedFileId(SmbFileHandleImpl f) throws SmbException
	{
		int fid = f.getFid();
        ByteBuffer bb = ByteBuffer.allocate(16);    
        byte[] file_id_byte_arr= bb.order(ByteOrder.LITTLE_ENDIAN).putInt(fid).array();
        return file_id_byte_arr;
	}
	
	public boolean setFileACL(ACE[] aceArray)
    {
    	try {
    	SmbFileHandleImpl f = openUnshared(O_RDWR, WRITE_DAC | WRITE_OWNER,DEFAULT_SHARING, 0, isDirectory() ? 1 : 0);
		byte[] file_id_byte_arr = getOpenedFileId(f);
        
        Smb2SetACLRequest req = new Smb2SetACLRequest(f.getTree().getConfig(),file_id_byte_arr,aceArray);
        SmbTreeHandleImpl h = ensureTreeConnected();
        
        //if the request is not made with the withOpen function then you will get a 0xC0000128 error (file closed)
         withOpen(h, Smb2CreateRequest.FILE_OPEN, WRITE_DAC | WRITE_OWNER, DEFAULT_SHARING, req);
         return true;
        }catch(Exception e)
        {
        	e.printStackTrace();
        }
        
        return false;
    }
    
    public boolean setFileOwner(SID newOwner)
    {
    	try {
        	SmbFileHandleImpl f = openUnshared(O_RDWR, WRITE_DAC | WRITE_OWNER,DEFAULT_SHARING, 0, isDirectory() ? 1 : 0);    
            byte[] file_id_byte_arr = getOpenedFileId(f);
            
            Smb2SetOwnerRequest req = new Smb2SetOwnerRequest(f.getTree().getConfig(),file_id_byte_arr,newOwner);
            SmbTreeHandleImpl h = ensureTreeConnected();
            
            //if the request is not made with the withOpen function then you will get a 0xC0000128 error (file closed)
            withOpen(h, Smb2CreateRequest.FILE_OPEN, WRITE_DAC | WRITE_OWNER, DEFAULT_SHARING, req);
            return true;
            
    		}catch(Exception e)
            {
            	e.printStackTrace();
            }
            
            return false;
    }
}
