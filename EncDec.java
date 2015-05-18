package encDec;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;

import javax.crypto.spec.IvParameterSpec;

import java.io.*;
import java.util.Calendar;
import java.util.ResourceBundle;
import javax.servlet.RequestDispatcher;

import javax.xml.bind.DatatypeConverter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.codec.binary.Base64;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;
//import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import sun.misc.BASE64Encoder;

/**
 * Servlet implementation class EncDec
 */
@WebServlet("/EncDec")
public class EncDec extends HttpServlet {
	   static Cipher cipher;

	    private static final long serialVersionUID = 1L;

	    private static final ResourceBundle RB = ResourceBundle.getBundle("encDec.LocalStrings");

	    private static final String ALGO = "AES";
	    private static final byte[] keyValue = 
	        new byte[] { 'A', 'b', 'c', 'd', 'e', 'f', 'g',
	        'h', 'i', 'j', 'k','l', 'm', 'n', 'o', 'p'};

	    private static Key generateKey() throws Exception {
		      Key key = new SecretKeySpec(keyValue, ALGO);
		      return key;
		}
	    public static String encrypt(String Data) throws Exception {
	      Key key = generateKey();
	      Cipher c = Cipher.getInstance(ALGO);
	      c.init(Cipher.ENCRYPT_MODE, key);
	      byte[] encVal = c.doFinal(Data.getBytes());
	      String encryptedValue = new BASE64Encoder().encode(encVal);
	      return encryptedValue;
	    }



	    @Override
	    public void doPost(HttpServletRequest request,
	                      HttpServletResponse response)
	        throws IOException, ServletException
	    {
	        doGet(request, response);
	    }


	    @Override
	    public void doGet(HttpServletRequest request,
	                      HttpServletResponse response)
	        throws IOException, ServletException 
	    {
	        String cipherText = "";
	        byte[] clearTextBytes;
	        byte[] decryptedBytes;

	        response.setContentType("text/html");
	        DateFormat df = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");

	        java.util.Date today = Calendar.getInstance().getTime();
	        String reportDate = df.format(today);
	        
	        System.out.println("Date :"+ reportDate);
	        
	        PrintWriter out = response.getWriter();
	        out.println("<html>");
	        out.println("<head>");
	        out.println("<script src=\"http://crypto-js.googlecode.com/svn/tags/3.1.2/build/rollups/aes.js\"></script>");
	        out.println("<script src=\"http://crypto-js.googlecode.com/svn/tags/3.1.2/build/rollups/pbkdf2.js\"></script>");
	        out.println("<script src=\"http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/enc-base64-min.js\"></script>");
	        out.println("<script src=\"http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/enc-utf16-min.js\"></script>");
	        out.println("<script src=\"http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/enc-base64-min.js\"></script>");
	        
	        out.println("<script src=\"http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/mode-ecb-min.js\"></script>");

	        String title = RB.getString("requestparams.title");
	        out.println("<title>" + "CMPE 272 Encryption & Decryption Services" + "</title>");
	        out.println("</head>");
	        out.println("<body bgcolor=\"white\">");
	        out.println("<h3>" + "CMPE 272 Encryption & Decryption Services" + "</h3>");
	        out.println("<h5>" + "The purpose of the application is to demonstrate encryption and decryption services, On the server sidei, Bouncy Castle Provider is used to create Cipher text. On the Client sidei, Google Crypto JS used to decrypt the data." + "</h5>");
	        String plainText = request.getParameter("plaintext");
	        String eText = request.getParameter("etext"); 
	        String key = request.getParameter("key");
	        out.println("<br>");
	        out.println("<P>");
	        out.print("<form action=\"");
	        out.print("EncDec\" ");
	        out.println("method=POST>");
	        out.println(RB.getString("requestparams.plaintext"));

	        System.out.println("encrypted string:" );

	        if (plainText != null) {
	            out.println("<textarea name=plaintext rows=3  cols=40 >"+plainText+" </textarea>");
	            
	            System.out.println("Plane string:"+plainText );
	        } else {
	            out.println("<textarea name=plaintext rows=3  cols=40 > </textarea>");
	        } 
	        out.println("<br>");
	        out.println("<input type=submit value=\"Encrypt\" >");
	        out.println("</form>");


	        if (plainText != null) {
	        try {  
	        	plainText =   plainText+" "+reportDate;
	        	KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
	        	keyGenerator.init(128);
	    	   SecretKey secretKey = keyGenerator.generateKey();
	    	   //cipher = Cipher.getInstance("AES");
	    	   System.out.println("Plain Text Before Encryption: " + plainText);

	       
	    	   String encryptedText = encrypt(plainText);
	    	   System.out.println("Decrypted  Text " + encryptedText);

	            out.println("key");
	            out.println(" : " + keyValue + "<br>");
	            out.println("Encrypted Text");
	            out.println(" : " + encryptedText + "<br>");
	            out.println("Decrypted Text");
	            out.println("<span id='output'></span>");
	            out.println("<br>");
	            out.println("<button onclick=\"myFunction()\">Click to decryp using google CryptoJS</button>");
	            out.println("<script>");
	            out.println("function myFunction() {");
	            System.out.println("encrypted string in java script is :" + encryptedText);
	            if (encryptedText != null) {
	                
	                out.println("var base64Key = \"QWJjZGVmZ2hpamtsbW5vcA==\";");
	                String keyForJS = new BASE64Encoder().encode(keyValue);
	                System.out.println("Key For JS :"+ keyForJS);
	                out.println("var key = CryptoJS.enc.Base64.parse('"+keyForJS+"');");

	                out.println("alert('text to decrypt 1');");  
	                out.println("var decrypted = CryptoJS.AES.decrypt('"+encryptedText+"',key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7});");
	                out.println("alert('text to decrypt 1');");   
	                
	                out.println("alert('"+plainText+"');"); 
	                out.println("var decryptedText = decrypted.toString( CryptoJS.enc.Utf8 );"); 
	                out.println("document.getElementById('output').innerHTML = \"<br>Decrypted text with date time=\"+decryptedText;");
	                
	            } else {
	                out.println("alert('No text to decrypt');");  
	            }
	            out.println("}");
	            out.println("</script>");
	        } catch (Exception ex) {
	                  ex.printStackTrace();
	        }
	            
	        } else {
	             System.out.println(" Empty String");
	        }
	        out.println("</body>");
	        out.println("</html>");
	    }


}
