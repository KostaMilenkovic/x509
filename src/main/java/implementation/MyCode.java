/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;

import code.GuiException;
import java.io.File;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import x509.v3.CodeV3;
import x509.v3.GuiV3;

/**
 *
 * @author milenkok
 */
public class MyCode extends CodeV3{
    
    public GuiV3 getGui(){
        return access;
    }

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
        super(algorithm_conf, extensions_conf);
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        return null;
    }

    @Override
    public void resetLocalKeystore() {
        return;
    }

    @Override
    public int loadKeypair(String string) {
        return 0;
    }

    @Override
    public boolean saveKeypair(String string) {
        return false;
    }

    @Override
    public boolean removeKeypair(String string) {
        return false;
    }

    @Override
    public boolean importKeypair(String string, String string1, String string2) {
        return false;
    }

    @Override
    public boolean exportKeypair(String string, String string1, String string2) {
        return false;
    }

    @Override
    public boolean signCertificate(String string, String string1) {
        return false;
    }

    @Override
    public boolean importCertificate(File file, String string) {
        return false;
    }

    @Override
    public boolean exportCertificate(File file, int i) {
        return false;
    }

    @Override
    public String getIssuer(String string) {
        return null;
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String string) {
        return null;
    }

    @Override
    public int getRSAKeyLength(String string) {
        return 0;
    }

    @Override
    public List<String> getIssuers(String string) {
        return null;
    }

    @Override
    public boolean generateCSR(String string) {
        return false;
    }
    
}
