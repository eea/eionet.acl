/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package eionet.acl;

/**
 *
 * @author Aris Katsanas <aka@eworx.gr>
 */
class InvalidPropertiesException extends Exception {
     /**
     * Constructor.
     * @param s - message
     */
    public InvalidPropertiesException(Throwable t, String s) {
        super(s, t);
    }

    /**
     * Constructor.
     *
     * @param s - message
     */
    public InvalidPropertiesException(String s) {
        super(s);
    }
}
