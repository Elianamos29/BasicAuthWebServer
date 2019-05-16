/*  Victor Cervantes
    CS361
    October 3, 2018
*/
/***********************************************************************

   SimpleWebServer.java


   This toy web server is used to illustrate security vulnerabilities.
   This web server only supports extremely simple HTTP GET requests.

   This file is also available at http://www.learnsecurity.com/ntk

***********************************************************************/

//package com.learnsecurity;                                

import java.io.*;                                         
import java.net.*;                                        
import java.util.*;                                       
import sun.misc.BASE64Decoder;
/*This will be used to pause between failed requests*/
import java.util.concurrent.TimeUnit;

public class BasicAuthWebServer {                            
    /* Run the HTTP server on this TCP port. */           
    private static final int PORT = 8080;
    /*This is a static number of max allowed failed requests i set it to 5 for testing purposes*/
    private static final int MAXREQUESTS = 6;
    /*The two arraylists below are to hold the ip number and number of failed requests in parllel*/
    private ArrayList<String> reqIP = new ArrayList<>();
    private ArrayList<Integer> numReq = new ArrayList<>();
    /* The socket used to process incoming connections from web clients */
    private static ServerSocket dServerSocket;            
  
    public BasicAuthWebServer () throws Exception 
    {          
	dServerSocket = new ServerSocket (PORT);          
    }                                                     

    public void run() throws Exception 
    {                 
    	while (true) 
        {                                   
    	    /* wait for a connection from a client */
    	    Socket s = dServerSocket.accept();           
    	    /* then process the client's request */
	        processRequest(s);                           
	    }                                                
    }                                                    

    private String checkPath (String pathname) throws Exception 
    {
    	File target = new File (pathname);
    	File cwd = new File (System.getProperty("user.dir"));
    	String s1 = target.getCanonicalPath();
    	String s2 = cwd.getCanonicalPath();
	
    	if (!s1.startsWith(s2))
    	    throw new Exception();
    	else 
    	    return s1;
    }

    /* Reads the HTTP request from the client, and
       responds with the file the user requested or
       a HTTP error code. */
    public void processRequest(Socket s) throws Exception 
    { 
	/* used to read data from the client */ 
	BufferedReader br = new BufferedReader (new InputStreamReader (s.getInputStream())); 

	/* used to write data to the client */
	OutputStreamWriter osw = new OutputStreamWriter (s.getOutputStream());  
    
	/* read the HTTP request from the client */
	String request = br.readLine();                    

	String command = null;                             
	String pathname = null;                            
    
	try 
    {
	    /* parse the HTTP request */
	    StringTokenizer st = 
		new StringTokenizer (request, " ");               
	    command = st.nextToken();                       
	    pathname = st.nextToken();                      
	} catch (Exception e) 
    {
	    osw.write ("HTTP/1.0 400 Bad Request\n\n");
	    osw.close();
	    return;
	}
    /*This will register the client's ip address*/
    String ipAddress = s.getRemoteSocketAddress().toString().substring(0, s.getRemoteSocketAddress().toString().length()-6);
    
    /*initializing a variable of numRequests*/
    int numRequests = 0;
    /*if the given ipaddress has already had failed requests the value of numRequests will be upated accordingly*/
    if(reqIP.contains(ipAddress))
    {
        numRequests = numReq.get(reqIP.indexOf(ipAddress));
    }
    logEntry("FileRequestslog.txt", command + " " + pathname + " " + ipAddress + "\n");
	if (command.equals("GET")) 
    {                    
        Credentials c = getAuthorization(br);
        /*added the parameter to ensure the requests will not be met if client has exceeded number of allowable failed requests*/
   	    if ((MAXREQUESTS >= numRequests) && (c != null) && (MiniPasswordManager.checkPassword(c.getUsername(), c.getPassword())))
        {
            String lastLogin = "First Time loging in";            
            try
            {
                /*sets lastLogin to last entry on login log for each client if there is no log the default is: "First time loging in"*/
                BufferedReader bufr = new BufferedReader(new FileReader(c.getUsername() + "login.txt"));
                String temp = "";
                while(temp != null)
                {
                    lastLogin = temp; 
                    temp = bufr.readLine();   
                }
            }
            catch(Exception e)
            {
            }
            /*This lets the client know the last time they logged in*/              
            osw.write("last login: " + lastLogin + "\n");
            serveFile(osw, pathname);
                            
            if(reqIP.contains(ipAddress))
            {
                int idx = reqIP.indexOf(ipAddress);
                reqIP.remove(idx);
                numReq.remove(idx);
            }
            logEntry(c.getUsername() + "login.txt", c.getUsername() + "\n");
        }
        else if(MAXREQUESTS < numRequests)
        {
            /*If the client exceeds the number of allowable failed requests they will no longer be prompted to login*/
            osw.write("You have exceeded the number of failed logins. Please contact the Administrator.");        
        }
        else 
        {
            logEntry("failedLogins.txt", ipAddress + " " + "\n"); //loging ip address of failed login client
            osw.write ("HTTP/1.0 401 Unauthorized\n");
            int x = 0;
              
            if(reqIP.contains(ipAddress))
            {
                x =(int)Math.pow(2,numReq.get(reqIP.indexOf(ipAddress)));
            }
            System.out.println("waiting..." + x + " seconds \nYou have had " + numRequests + " failed login attempts \nYour ip will be locked after " + MAXREQUESTS + " failed login attempts");
            TimeUnit.SECONDS.sleep(x);
             
            if(reqIP.contains(ipAddress))
            {
                int idx = reqIP.indexOf(ipAddress);
                numReq.set(idx, numReq.get(idx) + 1);
            }
            else
            {
                reqIP.add(ipAddress);
                numReq.add(1);                
            }
    		osw.write ("WWW-Authenticate: Basic realm=\"BasicAuthWebServer\"\n\n");
    	}
    }
    else if(command.equals("PUT"))
    {   
        //if request is PUT use storeFile method
        Credentials c = getAuthorization(br);
        if ((MAXREQUESTS >= numRequests) && (c != null) && (MiniPasswordManager.checkPassword(c.getUsername(), c.getPassword()))) 
        {   
            storeFile(br, osw, pathname);
            if(reqIP.contains(ipAddress))
            {
                int idx = reqIP.indexOf(ipAddress);
                reqIP.remove(idx);
                numReq.remove(idx);
            }
        }
        else if(MAXREQUESTS < numRequests)
        {
            osw.write("You have exceeded the number of failed login attempts. \nPlease contact the Administrator.");        
        }
        else 
        {
            logEntry("failedLogins.txt", ipAddress + " " + "\n"); //loging ip address of failed login client
    		osw.write ("HTTP/1.0 401 Unauthorized\n");
            int x = 0;
            if(reqIP.contains(ipAddress))
            {
                x = (int)Math.pow(2,numReq.get(reqIP.indexOf(ipAddress)));
            }
            System.out.println("waiting..." + x + " seconds \nYou have had " + numRequests + " failed login attempts \nYour ip will be locked after " + MAXREQUESTS + " failed login attempts");
            TimeUnit.SECONDS.sleep(x);
            if(reqIP.contains(ipAddress))
            {
                int idx = reqIP.indexOf(ipAddress);
                numReq.set(idx, numReq.get(idx) + 1);
            }         
            else
            {
                reqIP.add(ipAddress);
                numReq.add(1);                
            }
            osw.write ("WWW-Authenticate: Basic realm=\"BasicAuthWebServer\"\n\n");
    	}
    }    
    else 
    {                                         
	    /* if the request is a NOT a GET,
	    return an error saying this server
	    does not implement the requested command */
	    osw.write ("HTTP/1.0 501 Not Implemented\n\n");
    }                                               
	/* close the connection to the client */
	osw.close();                                    
    }                                                   

    private Credentials getAuthorization (BufferedReader br) {
	try {
	    String header = null;
	    while (!(header = br.readLine()).equals("")) {
		System.err.println (header);
		if (header.startsWith("Authorization:")) {
		    StringTokenizer st = new StringTokenizer(header, " ");
		    st.nextToken(); // skip "Authorization"
		    st.nextToken(); // skip "Basic"
		    return new Credentials(st.nextToken());
		}
	    }
	} catch (Exception e) {
	}
	return null;
    }

    public void serveFile (OutputStreamWriter osw,      
                           String pathname) throws Exception {
	FileReader fr=null;                                 
	int c=-1;                                           
	StringBuffer sb = new StringBuffer();
      
	/* remove the initial slash at the beginning
	   of the pathname in the request */
	if (pathname.charAt(0)=='/')                        
	    pathname=pathname.substring(1);                 
	
	/* if there was no filename specified by the
	   client, serve the "index.html" file */
	if (pathname.equals(""))                            
	    pathname="index.html";                          

	/* try to open file specified by pathname */
	try {                                               
	    fr = new FileReader (checkPath(pathname));                 
	    c = fr.read();                                  
	}                                                   
	catch (Exception e) {                               
	    /* if the file is not found,return the
	       appropriate HTTP response code  */
	    osw.write ("HTTP/1.0 404 Not Found\n\n");         
	    return;                                         
	}                                                   

	/* if the requested file can be successfully opened
	   and read, then return an OK response code and
	   send the contents of the file */
	osw.write ("HTTP/1.0 200 OK\n\n");                    
	while (c != -1) {       
            sb.append((char)c);                            
	    c = fr.read();                                  
	}                                                   
	osw.write (sb.toString());                                  
    }
    public void storeFile(BufferedReader br, OutputStreamWriter osw, String pathname) throws Exception
    {
    	FileWriter fw = null;
    	try
    	{
    		fw = new FileWriter(checkPath(pathname));
    		String s = br.readLine();
    		while(s != null)
    		{
    			fw.write(s + "\n");
    			s = br.readLine();
    		}
            fw.close();
    		osw.write("HTTP/1.0 201 Created\n");
    	}
    	catch(Exception e)
    	{
    		osw.write("HTTP/1.0 500 Internal Server Error");
    	}
    }
    public void logEntry(String filename, String record)
    {       
        try
        {   
    	    FileWriter fw = new FileWriter(filename, true);
    	    fw.write(getTimestamp() + " " + record);
    	    fw.close();
        }
        catch(Exception e)
        {
            return;
        }    
    }
    public String getTimestamp()
    {
    	return(new Date()).toString();
    }                                                       

    /* This method is called when the program is run from
       the command line. */
    public static void main (String argv[]) throws Exception { 
	if (argv.length == 1) {
	    /* Initialize MiniPasswordManager */
	    MiniPasswordManager.init(argv[0]);

	    /* Create a BasicAuthWebServer object, and run it */
	    BasicAuthWebServer baws = new BasicAuthWebServer();           
	    baws.run();                                             
	} else {
	    System.err.println ("Usage: java BasicAuthWebServer <pwdfile>");
	}
    }                                                          
}                                                              

class Credentials {
    private String dUsername;
    private String dPassword;
    public Credentials(String authString) throws Exception {
	authString = new String((new sun.misc.BASE64Decoder().decodeBuffer(authString)));
	StringTokenizer st = new StringTokenizer(authString, ":");
	dUsername = st.nextToken();
	dPassword = st.nextToken();
    }
    public String getUsername() {
	return dUsername;
    }
    public String getPassword() {
	return dPassword;
    }
}
