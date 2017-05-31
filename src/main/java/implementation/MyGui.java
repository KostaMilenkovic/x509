package implementation;

import code.GuiException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Set;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import x509.v3.GuiV3;

/**
 *
 * @author milenkok
 */
public class MyGui{
    private GuiV3 guiV3;
    
    public MyGui(GuiV3 guiV3) throws GuiException {
        this.guiV3 = guiV3;
    }   
    
    public GuiV3 getAccess(){
        return guiV3;
    }
    
    public void writeX509Certificate(X509Certificate certificate) throws Exception{
        Principal certificateSubject = certificate.getSubjectDN();
        LdapName ln = new LdapName(certificateSubject.toString());
        //certificate subject
        
        for(Rdn rdn : ln.getRdns()){
            switch(rdn.getType()){
                case "CN":
                    guiV3.setSubjectCommonName(rdn.toString().replaceFirst("CN=", ""));  
                    break;
                case "C":
                    guiV3.setSubjectCountry(rdn.toString().replaceFirst("C=", ""));  
                    break;
                case "S":
                    guiV3.setSubjectState(rdn.toString().replaceFirst("S=", ""));  
                    break;
                case "O":
                    guiV3.setSubjectOrganization(rdn.toString().replaceFirst("O=", ""));  
                    break;
                case "OU":
                    guiV3.setSubjectOrganizationUnit(rdn.toString().replaceFirst("OU=", ""));  
                    break;
                case "L":
                    guiV3.setSubjectLocality(rdn.toString().replaceFirst("L=", ""));  
                    break;
                    
            }
        }
        
        //certificate version
        guiV3.setVersion((certificate.getVersion())==3?2:1);
        //certificate serial number
        guiV3.setSerialNumber(certificate.getSerialNumber().toString());
        //certificate validity
        guiV3.setNotBefore(certificate.getNotBefore());
        guiV3.setNotAfter(certificate.getNotAfter());
        //issued by
        Principal issuerDN = certificate.getIssuerDN();
        String issuerString = issuerDN.toString().replace(" ", "");
        guiV3.setIssuer(issuerString);
        guiV3.setIssuerSignatureAlgorithm(certificate.getSigAlgName());
        //certificate version 3 extensions
        setExtensionFields(certificate);
        
    }

  
    private void setExtensionFields(X509Certificate cert) throws Exception {
//        //key identifier fields
//        SubjectKeyIdentifier sKID = new SubjectKeyIdentifier(cert.getExtensionValue(Extension.subjectKeyIdentifier.toString()));
//        AuthorityKeyIdentifier aKID = new AuthorityKeyIdentifier(cert.getExtensionValue(Extension.authorityKeyIdentifier.toString()));
//
//        //key identifier fields
//        if((aKID.getKeyIdentifier() != null) && (sKID.getKeyIdentifier() != null )) {
//            Principal issuerDN = cert.getIssuerDN();
//            LdapName ln2 = new LdapName(issuerDN.toString());
//
//            guiV3.setAuthorityKeyID(aKID.getKeyIdentifier().toString());
//            guiV3.setSubjectKeyID(sKID.getKeyIdentifier().toString());
//            guiV3.setAuthorityIssuer(ln2.getRdn(1).getValue().toString());
//            guiV3.setAuthoritySerialNumber(cert.getSerialNumber().toString());
//            guiV3.setEnabledKeyIdentifiers(true);
//        } else {
//          guiV3.setEnabledKeyIdentifiers(false);
//        }
//
//        //alternative name fields
//        Collection sANs = cert.getSubjectAlternativeNames();
//
//        if(sANs != null) {      
//            // each item of collection is a List, where List(0) - Integer that represents the type of alternative name and List(1) - the actual name
//            String sANField = "";
//            int i = 0;
//            for (Iterator iterator = sANs.iterator(); iterator.hasNext();) {
//              List<Object> nameTypePair = (List<Object>) iterator.next();   
//              Integer typeOfAlternativeName = (Integer)nameTypePair.get(0);
//              String alternativeName = (String) nameTypePair.get(1);
//              sANField += alternativeName;
//              if(i<sANs.size()-1) 
//                sANField += ",";
//              i++;
//            }
//            guiV3.setAlternativeName(5, sANField);
//        }

        //basic constraint fields

        byte[] extVal = cert.getExtensionValue(Extension.basicConstraints.toString());
        if (extVal != null) {
          Object obj = new ASN1InputStream(extVal).readObject();
          extVal = ((DEROctetString) obj).getOctets();
          obj = new ASN1InputStream(extVal).readObject();
          BasicConstraints basicConstraints = BasicConstraints.getInstance((ASN1Sequence) obj);
          guiV3.setCA(basicConstraints.isCA());
          if(basicConstraints.isCA()) {
            guiV3.setPathLen(basicConstraints.getPathLenConstraint().toString());
          }
        }


        //setting critical fields 0- key ids, 5-alt names, 8-basicConstraints
        Set<String> criticals = cert.getCriticalExtensionOIDs();
        if(criticals == null)
            return;
        criticals.forEach((criticalElement) -> {
          if(criticalElement.compareTo(Extension.subjectAlternativeName.toString()) == 0) {
            guiV3.setCritical(5, true);
          } else if (criticalElement.compareTo(Extension.basicConstraints.toString()) == 0) {
            guiV3.setCritical(8, true);
          }
        });
        guiV3.setCritical(0, false);
    }

  
 
}
