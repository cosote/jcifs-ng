package jcifs.setsecurity;

import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.util.SMBUtil;

public class Smb2SetSecurityInfoResponse extends ServerMessageBlock2Response{
	
    /**
     * @param config
     */
    public Smb2SetSecurityInfoResponse ( Configuration config ) {
        super(config);
    }


    /**
     * {@inheritDoc}
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat ( byte[] dst, int dstIndex ) {
        return 0;
    }


    /**
     * {@inheritDoc}
     * 
     * @throws SMBProtocolDecodingException
     *
     * @see jcifs.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat ( byte[] buffer, int bufferIndex ) throws SMBProtocolDecodingException {
        int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if ( structureSize != 2 ) {
            throw new SMBProtocolDecodingException("Expected structureSize = 2");
        }
        return 2;
    }

}
