package jcifs.setsecurity;

import jcifs.internal.util.SMBUtil;

public class SMBAdditionalUtils extends SMBUtil{
	
	
	public static int writeByteArr( byte[] src, byte[] dst, int dstIndex ) {
        for(int i = 0; i < src.length; i++){
            dst[dstIndex + i] = src[i];
        }
        return src.length;
    }
}
