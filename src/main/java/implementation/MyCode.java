/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;

import code.GuiException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import x509.v3.CodeV3;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 *
 * @author milenkok
 */
public class MyCode extends CodeV3{
    private MyGui myGui;
    private KeyPairGenerator keyGen;
    private KeyPair keyPair;
    private PKCS10CertificationRequest csr = null;
    private X509Certificate certificateToSign;
    private String selectedAlias;

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
        super(algorithm_conf, extensions_conf);
        myGui = new MyGui(access);
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        Enumeration<String> aliases = null;
        try {
            KeyStore ks = X509impl.loadKeyStore();
            aliases =  ks.aliases();
        } catch (Exception ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return aliases;
    }

    @Override
    public void resetLocalKeystore() {
        try {
            X509impl.getKeyStore().load(null,null);
            File keyStoreFile = new File(X509impl.getKeyStoreFileName());
            keyStoreFile.delete();
        } catch (Exception ex) {
          Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public int loadKeypair(String alias) {
        int result = -1;
        try {
            selectedAlias = alias;
            Certificate[] certs = X509impl.getKeyStore().getCertificateChain(alias);
            X509Certificate certificate;

            if(certs == null)
              certificate = (X509Certificate) X509impl.getKeyStore().getCertificate(alias);
            else
              certificate = (X509Certificate) certs[0];
            
            myGui.writeX509Certificate(certificate);
            
            //check if issuer is certificate authority
            Principal certificateIssuer = certificate.getIssuerDN();
            LdapName ln = new LdapName(certificateIssuer.toString());
            //certificate issuer
            String issuerAlias = null;
            for(Rdn rdn : ln.getRdns()){
                switch(rdn.getType()){
                    case "CN":
                        issuerAlias = rdn.toString().replaceFirst("CN=", "");  
                        break;
                }
            }
            
            
            issuerAlias = issuerAlias.replaceFirst("C=", "");
            X509Certificate issuerCertificate = (X509Certificate)X509impl.getKeyStore().getCertificate(issuerAlias);
            
            if(issuerCertificate==null)
                return 0;
            
            byte[] extVal = issuerCertificate.getExtensionValue(Extension.basicConstraints.toString());
            if (extVal != null) {
                Object obj = new ASN1InputStream(extVal).readObject();
                extVal = ((DEROctetString) obj).getOctets();
                obj = new ASN1InputStream(extVal).readObject();
                BasicConstraints basicConstraints = BasicConstraints.getInstance((ASN1Sequence) obj);
                if(basicConstraints.isCA())
                    return 1;
              
            }
            
            result = 0;
        } catch (Exception ex) {
          Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return result;
    }

    @Override
    public boolean saveKeypair(String alias) {
        boolean result = false;

        try {
            //initialize key generator
            keyGen = KeyPairGenerator.getInstance("DSA");
            keyGen.initialize(Integer.parseInt(myGui.getAccess().getPublicKeyParameter()));
            //generate key pair
            keyPair = keyGen.generateKeyPair();
            //generate certificate
            X509Certificate certificate = X509impl.generateCertificate(myGui.getAccess(), keyPair.getPublic(), keyPair.getPrivate(), true, null);
            Certificate certificates [] = {certificate};
            X509impl.getKeyStore().setKeyEntry(alias, keyPair.getPrivate(), X509impl.getKeyStorePassword().toCharArray(), certificates);
            X509impl.storeKeyStore();
            result = true;
        } catch (Exception ex) {
          Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return result;
    }

   
  @Override
  public boolean removeKeypair(String alias) {
    boolean result = false;
    
    try {
        if(X509impl.getKeyStore().containsAlias(alias)) {
            X509impl.getKeyStore().deleteEntry(alias);
            X509impl.storeKeyStore();
            result = true;
        }
    } catch (Exception ex) {
      Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    return result;
  }

    @Override
    public boolean importKeypair(String alias, String fileName, String password) {
        boolean result = false;

        try {
            KeyStore ks = KeyStore.getInstance("pkcs12");
            InputStream readStream = new FileInputStream(fileName);
            ks.load(readStream, password.toCharArray());
            readStream.close();
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            Key pKey = ks.getKey(alias, password.toCharArray());
            if((cert!=null)&&(pKey!=null)) {
                Certificate certs[] = {cert};
                if(!X509impl.getKeyStore().containsAlias(alias)) {
                    X509impl.getKeyStore().setKeyEntry(alias, pKey, X509impl.getKeyStorePassword().toCharArray(), certs);
                    X509impl.storeKeyStore();
                    result = true;
                }
            }
        } catch (Exception ex) {
          Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return result;
    }

    @Override
    public boolean exportKeypair(String alias, String fileName, String password) {
        boolean result = false;

        try {
            KeyStore.ProtectionParameter pp = new KeyStore.PasswordProtection(X509impl.getKeyStorePassword().toCharArray()); 
            KeyStore ks = KeyStore.getInstance("pkcs12");
            ks.load(null,null);
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) X509impl.getKeyStore().getEntry(alias, pp);
            Certificate certs[] = {entry.getCertificateChain()[0]};
            PrivateKey pKey = entry.getPrivateKey();
            ks.setKeyEntry(alias, pKey, password.toCharArray(), certs);
            OutputStream writeStream;

            writeStream = new FileOutputStream(fileName+".p12");
            ks.store(writeStream, password.toCharArray());
            writeStream.close();

        } catch (Exception ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return result;
    }
    
    @Override
    public boolean generateCSR(String alias) {
        boolean result = false;

        try {
            if(!X509impl.getKeyStore().containsAlias(alias))
                throw new Exception("unknown alias");
                
                PublicKey publicKey = X509impl.getKeyStore().getCertificate(alias).getPublicKey();
                
                KeyStore.ProtectionParameter pp = new KeyStore.PasswordProtection(X509impl.getKeyStorePassword().toCharArray());
                KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) X509impl.getKeyStore().getEntry(alias, pp);
                certificateToSign = (X509Certificate) entry.getCertificate();
                selectedAlias = alias;
                PrivateKey privateKey = entry.getPrivateKey();
                
               
                
                ContentSigner signGen = new JcaContentSignerBuilder("SHA1withDSA").build(privateKey);
                //date needed to sign x509 certificate
                PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(certificateToSign.getSubjectX500Principal(), publicKey);
                
                csr =  builder.build(signGen);
                
                PrintWriter output = new PrintWriter("C:\\Users\\milenkok\\Desktop\\demo.pem");

                JcaPEMWriter pem = new JcaPEMWriter(output);
                pem.writeObject(csr);
                pem.close();

                result = true;
                

        } catch (Exception ex) {
          Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return result;
    }
    
    @Override
    public boolean signCertificate(String issuerAlias, String algorithm) {
        boolean result = false;
        try {

            X509Certificate certificate = X509impl.signCertificate(csr,certificateToSign,issuerAlias);
            Certificate [] certificates = {certificate};
            
            
            KeyStore.ProtectionParameter pp = new KeyStore.PasswordProtection(X509impl.getKeyStorePassword().toCharArray());
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) X509impl.getKeyStore().getEntry(selectedAlias, pp);
            
            X509impl.getKeyStore().deleteEntry(selectedAlias);
            X509impl.getKeyStore().setKeyEntry(selectedAlias, entry.getPrivateKey(), X509impl.getKeyStorePassword().toCharArray(), certificates);
            X509impl.storeKeyStore();

            result = true;
        } catch (Exception ex) {
          Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return result;
    }
    
    //==========================================================================
    //TODO
    //==========================================================================

    @Override
    public boolean importCertificate(File file, String alias) {
        boolean result = false;
        try {
            Path fileLocation = Paths.get(file.getAbsolutePath());
            byte[] data = Files.readAllBytes(fileLocation);
            ByteArrayInputStream bIn = new ByteArrayInputStream(data);

            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bIn);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
            X509impl.getKeyStore().setKeyEntry(alias, keyGen.genKeyPair().getPrivate(), X509impl.getKeyStorePassword().toCharArray(), new Certificate[]{cert});
            result = true;
        } catch (Exception ex) {
          Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return result;
    }
    
    //==========================================================================
    //TODO
    //==========================================================================
    
    @Override
    public boolean exportCertificate(File file, int encoding) {
        boolean result = false;     
        try {
            KeyStore.ProtectionParameter pp = new KeyStore.PasswordProtection(X509impl.getKeyStorePassword().toCharArray());
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) X509impl.getKeyStore().getEntry(selectedAlias, pp);
            X509Certificate cert = (X509Certificate) entry.getCertificate();

            File file2 = new File(file.getAbsolutePath()+".cer");

            switch(encoding){
                case 0:
                    //DER
                    FileOutputStream os = new FileOutputStream(file2);
                    DEROutputStream dos = new DEROutputStream(os);
                    ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(cert.getEncoded()));

                    dos.writeObject(aIn.readObject());
                    dos.flush();
                    dos.close();
                    break;
                case 1:
                    //PEM
                    Writer writer = new FileWriter(file2);
                    PemWriter pem = new PemWriter(writer);
                    PemObject pog = new PemObject(cert.getType(), cert.getEncoded());
                    pem.writeObject(pog);
                    pem.flush();
                    pem.close();
                    break;
            }
            result = true;
        } catch (Exception ex) {
          Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return result;
    }


    @Override
    public String getIssuer(String alias) {
        String result = "";
        KeyStore.ProtectionParameter pp = new KeyStore.PasswordProtection(X509impl.getKeyStorePassword().toCharArray());
        try {
            X509Certificate certificate = (X509Certificate) X509impl.getKeyStore().getCertificate(alias);
            result = certificate.getIssuerDN().toString();
        } catch (Exception ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return result;
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String alias) {
        String result = null;
        try {
            X509Certificate certificate = (X509Certificate) X509impl.getKeyStore().getCertificate(alias);
            result = certificate.getSigAlgName();
        } catch (Exception ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return result;
    }

    @Override
    public int getRSAKeyLength(String alias) {
        return -1;
    }

    @Override
    public List<String> getIssuers(String alias) {
        List<String> result = new ArrayList();
        Enumeration<String> aliases;
        try {
            aliases = X509impl.getKeyStore().aliases();
            while (aliases.hasMoreElements()) {
                String currentAlias = aliases.nextElement();
                if(currentAlias.compareTo(alias) == 0)
                  continue;
                X509Certificate certificate = (X509Certificate) X509impl.getKeyStore().getCertificate(currentAlias);
                if(certificate.getBasicConstraints() >= 0) {
                  result.add(currentAlias);
                }
            }
        } catch (Exception ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
        return result;
    }


    
}
