from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import ssl
import time

class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
    def _deny_response(self):
        self.send_response(403)
        self.send_header('Content-type', 'text/html')
        self.end_headers()      

    def do_GET(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        self._set_response()

    def do_POST(self):
        start_time = time.time()
        content_length = int(self.headers['Content-Length']) 
        post_data = self.rfile.read(content_length)
        if(str(self.headers['Content-Type']).find('multipart/form-data') != -1):
            injection = ['<script>', 'data:']
            for obj in injection:
                if post_data.decode('UTF-8').find(obj) != -1:
                    log = "Status: BLOCK, Src Adr: " + str(self.headers['Host'])   
                    print(log)        
                    logging.warning(log)
                    end_time = time.time() 
                    elapsed_time = str(round(end_time - start_time, 7))
                    f = open("timefile.txt", "a")
                    f.write(elapsed_time + '\n')
                    f.close()
                    self._deny_response()
                    print('\n')
                    break
                else:
                    log = "Status: ALLOW, Src Adr: " + str(self.headers['Host'])
                    print(log + '\n')                
                    logging.info(log)   
                    end_time = time.time() 
                    elapsed_time = str(round(end_time - start_time, 7))
                    f = open("timefile.txt", "a")
                    f.write(elapsed_time +'\n')
                    f.close()
                    self._set_response()
                    print('\n')
                    break
        else:
            sql = ['admin', 'database']
            for obj in sql:       
                if post_data.decode('UTF-8').find(obj) != -1:
                    log = "Status: BLOCK, Src Adr: " + str(self.headers['Host'])     
                    print(log + '\n')            
                    logging.warning(log)
                    end_time = time.time() 
                    elapsed_time = str(round(end_time - start_time, 7))
                    f = open("timefile.txt", "a")
                    f.write(elapsed_time + '\n')
                    f.close()
                    self._deny_response()
                    print('\n')
                    break
                else:
                    log = "Status: ALLOW, Src Adr: " + str(self.headers['Host'])
                    print(log + '\n')   
                    logging.info(log)   
                    end_time = time.time() 
                    elapsed_time = str(round(end_time - start_time, 7))
                    f = open("timefile.txt", "a")
                    f.write(elapsed_time +'\n')
                    f.close()
                    self._set_response()
                    print('\n')
                    break


def run(server_class=HTTPServer, handler_class=S, port=4443):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/home/user/conf/cert.pem', '/home/user/conf/key.pem')
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    #logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    #logging.info('Stopping httpd...\n')

if __name__ == '__main__':
    from sys import argv
    logging.basicConfig(filename='py_log.log', filemode='w', format="%(asctime)s %(message)s")
    with open('timefile.txt', 'r+') as f:
        f.truncate(0)   
    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()