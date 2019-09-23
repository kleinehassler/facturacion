<?php 
    function p_obtener_aleatorio() {
        //return floor(rand() * 999000) + 990;    
        return mt_rand(100000,999999);
    }
    function getXades(){
        $Signature_number = p_obtener_aleatorio();        
        $SignedInfo_number = p_obtener_aleatorio(); 
        $SignedProperties_number = p_obtener_aleatorio();                 
        $Reference_ID_number = p_obtener_aleatorio();
        $SignatureValue_number = p_obtener_aleatorio();
        $Certificate_number = p_obtener_aleatorio();
        $Object_number = p_obtener_aleatorio();               
        $SignedPropertiesID_number = p_obtener_aleatorio();            
            $xades = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:etsi="http://uri.etsi.org/01903/v1.3.2#" Id="Signature'.$Signature_number.'">
<ds:SignedInfo Id="Signature-SignedInfo'.$SignedInfo_number.'">
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<ds:Reference Id="SignedPropertiesID'.$SignedPropertiesID_number.'" Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature'.$Signature_number.'-SignedProperties'.$SignedProperties_number.'">
<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<ds:DigestValue></ds:DigestValue>
</ds:Reference>
<ds:Reference URI="#Certificate'.$Certificate_number.'">
<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<ds:DigestValue></ds:DigestValue>
</ds:Reference>
<ds:Reference Id="Reference-ID-'.$Reference_ID_number.'" URI="#comprobante">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<ds:DigestValue></ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue Id="SignatureValue'.$SignatureValue_number.'">
</ds:SignatureValue>
<ds:KeyInfo Id="Certificate'.$Certificate_number.'">
<ds:X509Data>
<ds:X509Certificate>
</ds:X509Certificate>
</ds:X509Data>
<ds:KeyValue>
<ds:RSAKeyValue>
<ds:Modulus>
</ds:Modulus>
<ds:Exponent></ds:Exponent>
</ds:RSAKeyValue>
</ds:KeyValue>
</ds:KeyInfo>
<ds:Object Id="Signature'.$Signature_number.'-Object'.$Object_number.'"><etsi:QualifyingProperties Target="Signature'.$Signature_number.'"><etsi:SignedProperties Id="Signature'.$Signature_number.'-SignedProperties'.$SignedProperties_number.'"><etsi:SignedSignatureProperties><etsi:SigningTime></etsi:SigningTime><etsi:SigningCertificate><etsi:Cert><etsi:CertDigest><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue></ds:DigestValue></etsi:CertDigest><etsi:IssuerSerial><ds:X509IssuerName></ds:X509IssuerName><ds:X509SerialNumber></ds:X509SerialNumber></etsi:IssuerSerial></etsi:Cert></etsi:SigningCertificate></etsi:SignedSignatureProperties><etsi:SignedDataObjectProperties><etsi:DataObjectFormat ObjectReference="#Reference-ID-'.$Reference_ID_number.'"><etsi:Description>contenido comprobante</etsi:Description><etsi:MimeType>text/xml</etsi:MimeType></etsi:DataObjectFormat></etsi:SignedDataObjectProperties></etsi:SignedProperties></etsi:QualifyingProperties></ds:Object>
</ds:Signature>';
        return $xades;
    }
?>