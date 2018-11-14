/**
 * 
 */
package jcifs;

/**
 * @author jbornema
 *
 */
public class CIFSStatistics {

	private long doSend = 0;
	
	public void reset() {
		doSend = 0;
	}
	
	public long increaseDoSend() {
		return ++doSend;
	}
	
	public long getDoSend() {
		return doSend;
	}
}
