//package implementation;
//
//import code.GuiException;
//import java.io.ByteArrayInputStream;
//import java.io.File;
//import java.io.FileInputStream;
//import java.io.FileOutputStream;
//import java.io.FileWriter;
//import java.io.IOException;
//import java.io.InputStream;
//import java.io.OutputStream;
//import java.io.Writer;
//import java.nio.file.Files;
//import java.nio.file.Path;
//import java.nio.file.Paths;
//import java.security.Key;
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.KeyStore;
//import java.security.KeyStore.PasswordProtection;
//import java.security.KeyStore.PrivateKeyEntry;
//import java.security.KeyStore.ProtectionParameter;
//import java.security.PrivateKey;
//import java.security.cert.Certificate;
//import java.security.cert.CertificateFactory;
//import java.security.cert.X509Certificate;
//import java.util.ArrayList;
//import java.util.Enumeration;
//import java.util.List;
//import java.util.logging.Level;
//import java.util.logging.Logger;
//import model.UIParameters;
//import org.bouncycastle.asn1.ASN1InputStream;
//import org.bouncycastle.asn1.DEROutputStream;
//import org.bouncycastle.util.io.pem.PemWriter;
//import org.bouncycastle.jce.PKCS10CertificationRequest;
//import org.bouncycastle.util.encoders.Base64;
//import org.bouncycastle.util.io.pem.PemObject;
//import util.UIUtils;
//import util.X509Utils;
//import x509.v3.CodeV3;
//import x509.v3.GuiV3;
//
//public class MyCode1 extends CodeV3 {
//  private KeyPairGenerator keyGen;
//  private KeyPair keyPair;
//  private String selectedKeyPair = null;
//  
//  public MyCode1(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
//    super(algorithm_conf, extensions_conf);
//  }
//  
//  public GuiV3 getAccess() {
//    return access;
//  }
//
//  @Override
//  public Enumeration<String> loadLocalKeystore() {
//    try {
//      KeyStore ks = X509Utils.getInstance().loadKeyStore();
//      return ks.aliases();
//    } catch (Exception ex) {
//      Logger.getLogger(MyCode1.class.getName()).log(Level.SEVERE, null, ex);
//    }
//    return null;
//  }
//
//  @Override
//  public void resetLocalKeystore() {
//    try {
//      X509Utils.getInstance().getKeyStore().load(null,null);
//      File keyStoreFile = new File(X509Utils.getKeyStoreFileName());
//      keyStoreFile.delete();
//    } catch (Exception ex) {
//      Logger.getLogger(MyCode1.class.getName()).log(Level.SEVERE, null, ex);
//    }
//  }
//
//  @Override
//  public int loadKeypair(String string) {
//    int result = -1;
//    
//    try {
//      Certificate[] certs = X509Utils.getInstance().getKeyStore().getCertificateChain(string);
//      X509Certificate cert;
//      
//      if(certs == null) {
//        cert = (X509Certificate) X509Utils.getInstance().getKeyStore().getCertificate(string);
//      } else {
//        cert = (X509Certificate) certs[0];
//      }
//      
//      result = UIUtils.mapCertificateToUI(access, cert);
//      if(result!=-1) {
//        selectedKeyPair = string;
//      }
//    } catch (Exception ex) {
//      Logger.getLogger(MyCode1.class.getName()).log(Level.SEVERE, null, ex);
//    }
//    return result;
//  }
//  
//  @Override
//  public boolean saveKeypair(String string) {
//    boolean res = true;
//    
//    UIParameters uiParams = UIUtils.mapUIToModel(access, string);
//    
//    try {
//      keyGen = KeyPairGenerator.getInstance("DSA");
//      keyGen.initialize(Integer.parseInt(uiParams.getKeyLength()));
//      keyPair = keyGen.generateKeyPair();
//      X509Certificate cert = X509Utils.getInstance().generateCertificate(uiParams, keyPair.getPublic(), keyPair.getPrivate(), true, null);
//      Certificate certs [] = {cert};
//      
//      X509Utils.getInstance().getKeyStore().setKeyEntry(uiParams.getName(), keyPair.getPrivate(), X509Utils.getKeyStorePassword().toCharArray(), certs);
//      X509Utils.getInstance().storeKeyStore();
//    } catch (IOException ex) {
//      Logger.getLogger(MyCode1.class.getName()).log(Level.SEVERE, null, ex);
//    } catch (Exception ex) {
//      Logger.getLogger(MyCode1.class.getName()).log(Level.SEVERE, null, ex);
//    }
//    
//    return res;
//  }
//
//  @Override
//  public boolean removeKeypair(String string) {
//    boolean result = false;
//    
//    try {
//      if(X509Utils.getInstance().getKeyStore().containsAlias(string)) {
//         X509Utils.getInstance().getKeyStore().deleteEntry(string);
//         X509Utils.getInstance().storeKeyStore();
//         result = true;
//      }
//    } catch (Exception ex) {
//      Logger.getLogger(MyCode1.class.getName()).log(Level.SEVERE, null, ex);
//    }
//    
//    return result;
//  }
//
//  //String keypair_name, String file_name, String password
//  @Override
//  public boolean importKeypair(String string, String string1, String string2) {
//    boolean result = false;
//    
//    try {
//      KeyStore ks = KeyStore.getInstance("pkcs12");
//      InputStream readStream = new FileInputStream(string1);
//      ks.load(readStream, string2.toCharArray());
//      readStream.close();
//      X509Certificate cert = (X509Certificate) ks.getCertificate(string);
//      Key pKey = ks.getKey(string, string2.toCharArray());
//      if((cert!=null)&&(pKey!=null)) {
//        Certificate certs[] = {cert};
//        if(!X509Utils.getInstance().getKeyStore().containsAlias(string)) {
//          X509Utils.getInstance().getKeyStore().setKeyEntry(string, pKey, X509Utils.getKeyStorePassword().toCharArray(), certs);
//          X509Utils.getInstance().storeKeyStore();
//          result = true;
//        }
//      }
//    } catch (Exception ex) {
//      Logger.getLogger(MyCode1.class.getName()).log(Level.SEVERE, null, ex);
//    }
//    
//    return result;
//  }
//
//  //String keypair_name, String file_name, String password
//  @Override
//  public boolean exportKeypair(String string, String string1, String string2) {
//    boolean result = false;
//    
//    try {
//      ProtectionParameter pp = new KeyStore.PasswordProtection(X509Utils.getKeyStorePassword().toCharArray()); 
//      KeyStore ks = KeyStore.getInstance("pkcs12");
//      ks.load(null,null);
//      PrivateKeyEntry entry = (PrivateKeyEntry) X509Utils.getInstance().getKeyStore().getEntry(string, pp);
//      Certificate certs[] = {entry.getCertificateChain()[0]};
//      PrivateKey pKey = entry.getPrivateKey();
//      ks.setKeyEntry(string, pKey, string2.toCharArray(), certs);
//      OutputStream writeStream;
//    
//      writeStream = new FileOutputStream(string1+".p12");
//      ks.store(writeStream, string2.toCharArray());
//      writeStream.close();
//      
//    } catch (Exception ex) {
//      Logger.getLogger(MyCode1.class.getName()).log(Level.SEVERE, null, ex);
//    }
//    
//    return result;
//  }
//
//  //string issuer, string algorithm
//  @Override
//  public boolean signCertificate(String string, String string1) {
//    boolean result = false;
//    
//    ProtectionParameter pp = new PasswordProtection(X509Utils.getKeyStorePassword().toCharArray());
//    try {
//      
//      PrivateKeyEntry issuerEntry = (PrivateKeyEntry) X509Utils.getInstance().getKeyStore().getEntry(string, pp);
//      PrivateKeyEntry subjectEntry = (PrivateKeyEntry) X509Utils.getInstance().getKeyStore().getEntry(selectedKeyPair, pp);
//      
//      X509Certificate cert = X509Utils.signCertificate(subjectEntry, issuerEntry);
//      Certificate [] chain = {cert};
//      
//      X509Utils.getInstance().getKeyStore().deleteEntry(selectedKeyPair);
//      X509Utils.getInstance().getKeyStore().setKeyEntry(selectedKeyPair, subjectEntry.getPrivateKey(), X509Utils.getKeyStorePassword().toCharArray(), chain);
//      X509Utils.getInstance().storeKeyStore();
//      
//      result = true;
//    } catch (Exception ex) {
//      Logger.getLogger(MyCode1.class.getName()).log(Level.SEVERE, null, ex);
//    }
//    
//    return result;
//  }
//
//  @Override
//  public boolean importCertificate(File file, String string) {
//    boolean result = false;
//    
//    try {
//      Path fileLocation = Paths.get(file.getAbsolutePath());
//      byte[] data = Files.readAllBytes(fileLocation);
//      ByteArrayInputStream bIn = new ByteArrayInputStream(data);
//      
//      X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bIn);
//      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
//      X509Utils.getInstance().getKeyStore().setKeyEntry(string, keyGen.genKeyPair().getPrivate(), X509Utils.getKeyStorePassword().toCharArray(), new Certificate[]{cert});
//      result = true;
//    } catch (Exception ex) {
//      Logger.getLogger(MyCode1.class.getName()).log(Level.SEVERE, null, ex);
//    }
//    
//    return result;
//  }
//
//  //i=0->DER, i=1->PEM
//  @Override
//  public boolean exportCertificate(File file, int i) {
//    boolean result = false;
//    ProtectionParameter pp = new KeyStore.PasswordProtection(X509Utils.getKeyStorePassword().toCharArray());
//    PrivateKeyEntry entry;
//    try {
//      entry = (PrivateKeyEntry) X509Utils.getInstance().getKeyStore().getEntry(selectedKeyPair, pp);
//      X509Certificate cert = (X509Certificate) entry.getCertificate();
//      
//      File file2 = new File(file.getAbsolutePath()+".cer");
//      
//      if(i==0) {
//        //DER
//        FileOutputStream os = new FileOutputStream(file2);
//        DEROutputStream dos = new DEROutputStream(os);
//        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(cert.getEncoded()));
//        
//        dos.writeObject(aIn.readObject());
//        dos.flush();
//        dos.close();
//      } else {
//        //PEM
//        Writer writer = new FileWriter(file2);
//        PemWriter pem = new PemWriter(writer);
//        PemObject pog = new PemObject(cert.getType(), cert.getEncoded());
//        pem.writeObject(pog);
//        pem.flush();
//        pem.close();
//      }
//      result = true;
//    } catch (Exception ex) {
//      Logger.getLogger(MyCode1.class.getName()).log(Level.SEVERE, null, ex);
//    }
//    
//    return result;
//  }
//
//  @Override
//  public String getIssuer(String string) {
//    String result = "";
//    ProtectionParameter pp = new KeyStore.PasswordProtection(X509Utils.getKeyStorePassword().toCharArray());
//    try {
//      PrivateKeyEntry entry = (PrivateKeyEntry) X509Utils.getInstance().getKeyStore().getEntry(string, pp);
//      X509Certificate cert = (X509Certificate) entry.getCertificate();
//      result = cert.getIssuerDN().toString();
//    } catch (Exception ex) {
//      Logger.getLogger(MyCode1.class.getName()).log(Level.SEVERE, null, ex);
//    }
//    return result;
//  }
//
//  @Override
//  public String getIssuerPublicKeyAlgorithm(String string) {
//    String result = null;
//    try {
//      X509Certificate cert = (X509Certificate) X509Utils.getInstance().getKeyStore().getCertificate(string);
//      result = cert.getSigAlgName();
//    } catch (Exception ex) {
//      Logger.getLogger(MyCode1.class.getName()).log(Level.SEVERE, null, ex);
//    }
//    return result;
//  }
//
//  @Override
//  public int getRSAKeyLength(String string) {
//    return -1;
//  }
//
//  @Override
//  public List<String> getIssuers(String string) {
//    List<String> result = new ArrayList();
//    Enumeration<String> aliases;
//    try {
//      aliases = X509Utils.getInstance().getKeyStore().aliases();
//      while (aliases.hasMoreElements()) {
//          String alias = aliases.nextElement();
//          if(alias.compareTo(string) == 0)
//            continue;
//          X509Certificate cert = (X509Certificate) X509Utils.getInstance().getKeyStore().getCertificate(alias);
//          if(cert.getBasicConstraints() >= 0) {
//            result.add(alias);
//          }
//      }
//      
//    } catch (Exception ex) {
//      Logger.getLogger(MyCode1.class.getName()).log(Level.SEVERE, null, ex);
//    }
//    if(result.isEmpty())
//      result=null;
//    return result;
//  }
//
//  //String keypair_name
//  @Override
//  public boolean generateCSR(String string) {
//    boolean result = false;
//    
//    try {
//      if(X509Utils.getInstance().getKeyStore().containsAlias(string)) {
//        ProtectionParameter pp = new PasswordProtection(X509Utils.getKeyStorePassword().toCharArray());
//        PrivateKeyEntry entry = (PrivateKeyEntry) X509Utils.getInstance().getKeyStore().getEntry(string, pp);
//        X509Certificate cert = (X509Certificate) entry.getCertificate();
//        PrivateKey pKey = entry.getPrivateKey();
//        PKCS10CertificationRequest pkcs10Request = new PKCS10CertificationRequest("SHA1withDSA",cert.getSubjectX500Principal(),cert.getPublicKey(), null, pKey);
//        
//        String base64PKCS10 = new String(Base64.encode(pkcs10Request.getEncoded()));
//        result = true;
//      }
//    } catch (Exception ex) {
//      Logger.getLogger(MyCode1.class.getName()).log(Level.SEVERE, null, ex);
//    }
//    
//    return result;
//  }
//  
//}
