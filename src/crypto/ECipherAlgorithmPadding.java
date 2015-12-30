/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package crypto;

/**
 *
 * @author y0n1 <y0n1@outlook.com>
 */
public enum ECipherAlgorithmPadding {
    NoPadding,
    ISO10126Padding,
    OAEPPadding,
    PKCS1Padding,
    PKCS5Padding,
    SSL3Padding    
}
