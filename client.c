#include <stdio.h>
#include <stdlib.h>
#include <tidy/tidy.h>
#include <tidy/buffio.h>
#include <curl/curl.h>
#include <string.h>
#include <json/json.h> 
//#define FALSE 0
#include <unistd.h>
#include <signal.h>
#include <libwebsockets.h>
struct info
{
	char userid[100];
	char pass[100];
	char client_auth_token[100];
	char interapptivity_userid[100];
};

struct info a;
struct session_data {
	int fd;
};
struct lws *wsii;
TidyDoc tdoc;
TidyBuffer docbuf = {0};
char sessionkey[100];
char res[100];
char endpoint[100];
static int destroy_flag = 0;
static int connection_flag = 0;
static int writeable_flag = 0;
const char *csrftoken;
const char *captcha;
char url[100]="http://10.142.49.11:8080/";
//char url[100]="https://alexa.interapptivity.com/";

char int_userid[200];;
char client_token[200];

/*   function prototyoe */
unsigned char *post();
void *dumpNode(TidyDoc doc, TidyNode tnod, int);
void captcha_image();
int jsonparse(unsigned char *);
char* auth_post();
char *auth_jsonparse(unsigned char *);
int socket_connection(char *);
static int websocket_write_back(struct lws *, char *, int);
static int ws_service_callback(struct lws *,enum lws_callback_reasons, void *,void *, size_t);

static void INT_HANDLER(int signo) {
	printf("Inside the interrupt handler");
	destroy_flag = 1;
}

uint write_cb(char *in, uint size, uint nmemb, TidyBuffer *out)
{
	uint r;
	r = size * nmemb;
	tidyBufAppend(out, in, r);
	return r;
}

int getrequest()
{

	printf("get %s",url);

	FILE *fptr;
	char *token;
	CURL *curl;
	CURL *curl_handle;
	CURLcode err;
	unsigned char *buff;
	unsigned char *buffer;
	char curl_errbuf[CURL_ERROR_SIZE];
	TidyBuffer tidy_errbuf = {0};		
	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);
	printf("\n\nGET request to get Registration page\n\n");
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	tdoc = tidyCreate();
	tidyOptSetBool(tdoc, TidyForceOutput, yes); 
	tidyOptSetInt(tdoc, TidyWrapLen, 4096);
	tidySetErrorBuffer(tdoc, &tidy_errbuf);
	tidyBufInit(&docbuf);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &docbuf);
	err=curl_easy_perform(curl);
	if(!err) {
		err = tidyParseBuffer(tdoc, &docbuf); 
		//printf( "\nResponse for GET Request:\n\n%s", docbuf.bp );
		buff=(unsigned char *) malloc(strlen(docbuf.bp)*sizeof(unsigned char));	
		memcpy(buff,docbuf.bp,strlen(docbuf.bp));
		//printf("Response for GET request (stored in buffer) %s", buff);
		fptr = fopen("Registration.html", "w");
		if (fptr) {    

			fwrite(buff,sizeof(unsigned char),strlen(buff),fptr);
			fclose(fptr) ;   
		}	 

		if(err >= 0) {
			err = tidyCleanAndRepair(tdoc); 
			if(err >= 0) {
				err = tidyRunDiagnostics(tdoc); 
				if(err >= 0) {
					dumpNode(tdoc, tidyGetRoot(tdoc), 0); 
				}

			}
		}
	}
	else
	{
		fprintf(stderr, "%s\n", curl_errbuf);
	}

	//	tidyBufFree(&docbuf);
	tidyBufFree(&tidy_errbuf);
	//	tidyRelease(tdoc);

	return 0;

}


static int websocket_write_back(struct lws *wsi_in, char *str, int str_size_in) {

	if (str == NULL || wsi_in == NULL)
	{
		printf("No message\n");

		return -1;
	}
	printf("The message got is=%s",str);
	int n;
	int len;
	char *out = NULL;
	if (str_size_in < 1) 
		len = strlen(str);
	else
		len = str_size_in;
	out = (char *)malloc(sizeof(char)*(LWS_SEND_BUFFER_PRE_PADDING + len + LWS_SEND_BUFFER_POST_PADDING));
	memcpy (out + LWS_SEND_BUFFER_PRE_PADDING, str, len );
	//printf("After padding=%s",out + LWS_SEND_BUFFER_PRE_PADDING);
	n = lws_write(wsi_in, out + LWS_SEND_BUFFER_PRE_PADDING, len, LWS_WRITE_TEXT);
	//printf("Return value of n =%d",n);
	free(out);
	return n;
}


static int ws_service_callback(struct lws *wsi,enum lws_callback_reasons reason, void *user,void *in, size_t len){
	switch (reason) {
		case LWS_CALLBACK_CLIENT_ESTABLISHED:
			printf("[Main Service] Connect with server success.\n");
			connection_flag = 1;
			break;
		case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
			printf("[Main Service] Connect with server error.\n");
			destroy_flag = 1;
			connection_flag = 0;
			break;
		case LWS_CALLBACK_CLOSED:
			printf("[Main Service] LWS_CALLBACK_CLOSED\n");
			destroy_flag = 1;
			connection_flag = 0;
			break;
		case LWS_CALLBACK_CLIENT_RECEIVE:
			printf("[Main Service] Client received:%s\n", (char *)in);
			if (writeable_flag)
				destroy_flag = 1;
			break;
		case LWS_CALLBACK_CLIENT_WRITEABLE :
			printf("[Main Service] On writeable is called. send byebye message\n");
			websocket_write_back(wsi, "Byebye! See you later", -1);
			writeable_flag = 1;
			break;
		default:
			break;
	}
	return 0;
}


static void *pthread_routine(){
	printf("[pthread_routine] Good day. This is pthread_routine.\n");
	while(1)
	{
		char m[255];
		printf("AM going to get the input\n");
		fgets(m,sizeof(m),stdin);
		printf("After fgets()\n");
		websocket_write_back(wsii, m, -1);
		printf("------");
		sleep(10);
	}
	//lws_callback_on_writable(wsii);
}


int socket_connection(char *endpt)

{  
	char *end1;
	char *token;
	char *token1;
	int port;
	char host[100];
	int i;
	char final[100];
	printf("\n\t\t\t\t************Websocket connection**********\n\n\n");
	struct sigaction act;
	act.sa_handler = INT_HANDLER;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction( SIGINT, &act, 0);
	struct lws_context *context = NULL;
	struct lws_context_creation_info info;
	struct lws *wsi = NULL;
	struct lws_protocols protocol;
	memset(&info, 0, sizeof info);
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.iface = NULL;
	info.protocols = &protocol;
	info.ssl_cert_filepath = NULL;
	info.ssl_private_key_filepath = NULL;
	info.extensions = lws_get_internal_extensions();
	info.gid = -1;
	info.uid = -1;
	info.options = 0;
	protocol.name  = "my-echo-protocol";
	protocol.callback = &ws_service_callback;
	protocol.per_session_data_size = sizeof(struct session_data);
	protocol.rx_buffer_size = 0;
	protocol.id = 0;
	protocol.user = NULL;
	end1=endpt+7;
	for(i=0;i<20;i++)
	{
		final[i]=*end1;
		end1++;
	}
	printf("%s",final);
	token=strtok(final,":");
	token1=strtok(NULL,":");
	sprintf(host, "%s:%s",token,token1);
	port=atoi(token1);
	context = lws_create_context(&info);
	printf("[Main] context created.\n");
	if (context == NULL) {
		printf("[Main] context is NULL.\n");
		return -1;
	}
	printf("\n\n\ntoken(ip_address)-------%s  port----- %d host -----%s\n\n\n",token,port,host);
	//wsi = lws_client_connect(context,"10.142.49.11",8080,0,"/","10.142.49.11:8080", NULL, protocol.name, -1);
	wsi = lws_client_connect(context,token,port,0,"/",host, NULL, protocol.name, -1);
	if (wsi == NULL) {
		printf("[Main] wsi create error.\n");
		return -1;
	}
	printf("[Main] wsi create success.\n");
	wsii = wsi;
	pthread_t pid;
	pthread_create(&pid, NULL, pthread_routine, NULL);
	while(!destroy_flag){
		//printf("lws_service calling\n");
		lws_service(context, 50);
	}
	lws_context_destroy(context);
	return 0;
}

char *rem(char *str)
{
	int l=strlen(str);
	int i,j=0;
	for(i=1;i<l-1;i++)
	{
		res[j++]=str[i];
	}
	res[j]='\0';
	return res;
}


char *auth_post()
{
	printf("\n\t\t\t\t**********Authentication started***********\n\n");
	//struct info b;
	char str[100];
	char url_auth[100];
	FILE *fptr;
	FILE *fptr1;
	CURLcode res;
	fptr = fopen("RDK_information.txt", "r");
	if(fptr)
	{
		while (fscanf (fptr,"%s %s %s %s",a.userid,a.pass,a.client_auth_token,a.interapptivity_userid)!=EOF)
			sprintf(str, "rdk_interapptivity_user=%s&rdk_client_auth_token=%s",a.interapptivity_userid,a.client_auth_token);
		printf("string for authentication POST\n%s", str);

	}
	fclose(fptr);
	sprintf(url_auth, "%sRDK/login/",url);
	CURL *curl;
	char *buffer=(char*)malloc(500*sizeof(char));
	char ch;
	char *buffer1;
	curl = curl_easy_init();
	fptr = fopen("auth_post.txt", "w+");
	curl_easy_setopt(curl, CURLOPT_URL,url_auth);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);
	curl_easy_setopt(curl,CURLOPT_POSTFIELDS,str);
	printf("\n\n*******POST in Authentication part*******\n\n");
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, fptr);
	curl_easy_perform(curl);
	fclose(fptr);
	fptr = fopen("auth_post.txt", "r");
	buffer1=buffer;
	while(1)
	{
		ch=fgetc(fptr);
		if(ch==EOF)
			break;
		else
		{
			*buffer=ch;
			buffer++;
		}

	}
	printf("\n********Response after Authentication********\n\n%s\n\n",buffer1);
	//printf("%d",strlen(buffer1))
	fclose(fptr);
	curl_easy_cleanup(curl);
	curl_global_cleanup();
	return buffer1;
}


unsigned char *post()
{
	char name[100];
	char pass[100];
	char email[100];
	char str[600];
	char url_post[100];
	char captcha_name[100];
	char *post_res;
	long numbytes;
	printf("\nEnter the username \n");
	scanf("%s",name);
	printf("Enter the email\n");
	scanf("%s",email);
	printf("Enter the password \n");
	scanf("%s", pass);
	printf("Enter the captcha from %s\n",captcha);
	scanf("%s",captcha_name);
	//sprintf(str, "csrfmiddlewaretoken=%s&username=%s&email=%s&password=%s&captcha_0=%s&captcha_1=%s",csrftoken,name,email,pass,captcha,captcha_name);
	sprintf(str, "username=%s&email=%s&password=%s&captcha_0=%s&captcha_1=%s",name,email,pass,captcha,captcha_name);
	//printf("POST  %s",str);
	CURL *curl;
	CURLcode res;
	CURLcode err;
	FILE *fptr;
	sprintf(url_post, "%sRDK/register/",url);
	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();
	fptr = fopen("post_response.txt", "w+");
	if(curl) {

		curl_easy_setopt(curl, CURLOPT_URL, url_post);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);
		curl_easy_setopt(curl,CURLOPT_POSTFIELDS,str);	
		printf("\n\n*******POST in Registration part*******\n\n");
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fptr);
		curl_easy_perform(curl);
		fclose(fptr);
	}
	fptr = fopen("post_response.txt", "r");
	fseek(fptr, 0L, SEEK_END);
	numbytes = ftell(fptr);
	fseek(fptr, 0L, SEEK_SET);	
	post_res = (char*)calloc(numbytes, sizeof(char));
	fread(post_res, sizeof(char), numbytes, fptr);
	//printf("Read Buffer: %s\n",post_res);	
	fclose(fptr);
	curl_easy_cleanup(curl);
	curl_global_cleanup();
	return post_res;
}


char * auth_jsonparse(unsigned char *auth_response)
{

	FILE *fptr;
	json_object * jobj10 = json_tokener_parse(auth_response);     
	json_object * jobj11 = json_tokener_parse(auth_response);
	jobj10 = json_object_object_get(jobj10, "session_key_websock");
	jobj11 = json_object_object_get(jobj11, "websocket_url");
	strcpy(sessionkey,json_object_to_json_string(jobj10));
	strcpy(endpoint,json_object_to_json_string(jobj11));
	printf("\n After parsing JSON message\n\n");
	printf("\nsessionkey= %s\nendpoint = %s\n",sessionkey,endpoint);
	strcpy(sessionkey,rem(sessionkey));
	//printf("after remove=%s",sessionkey);
	strcpy(endpoint,rem(endpoint));
	//printf("after remove1=%s",endpoint);
	return endpoint;
}


int jsonparse(unsigned char *response)
{
	char username[100];
	char password[100];
	char client_auth[100], int_user[100];
	char *b1=NULL;	
	FILE *fptr;
	json_object * jobj10 = json_tokener_parse(response);     
	json_object * jobj11 = json_tokener_parse(response);
	json_object * jobj12 = json_tokener_parse(response);
	json_object * jobj13 = json_tokener_parse(response);
	jobj10 = json_object_object_get(jobj10, "username");
	jobj11 = json_object_object_get(jobj11, "password");
	jobj12 = json_object_object_get(jobj12, "client_auth_token");
	jobj13 = json_object_object_get(jobj13, "interapptivity_user");
	strcpy(username,json_object_to_json_string(jobj10));
	strcpy(password,json_object_to_json_string(jobj11));
	strcpy(client_auth,json_object_to_json_string(jobj12));
	strcpy(int_user,json_object_to_json_string(jobj13));
	printf("\n\n After JSON  parsing\n\n");
	printf("\nuser id=%s\npassword=%s\nclient_auth_token=%s\ninterapptivity_user=%s\n",username,password,client_auth,int_user);
	strcpy(a.client_auth_token,rem(client_auth));
	printf("client token %s\n",a.client_auth_token);
	strcpy(a.interapptivity_userid,rem(int_user));
	printf("client token %s\n",a.interapptivity_userid);
	strcpy(a.userid,username);	
	strcpy(a.pass,password);
	fptr = fopen("RDK_information.txt", "w+");
	fprintf(fptr, "%s\n%s\n%s\n%s\n",a.userid,a.pass,a.client_auth_token,a.interapptivity_userid); 
	fclose(fptr);   
	return 0;
}


void *dumpNode(TidyDoc doc, TidyNode tnod, int indent)
{

	TidyNode child;
	int temp = 0;
	for(child = tidyGetChild(tnod); child; child = tidyGetNext(child) ) 
	{
		ctmbstr name = tidyNodeGetName(child);
		if(name) {

			TidyAttr attr;
			// printf("%*.*s%s ", indent, indent, "<", name);
			for(attr=tidyAttrFirst(child); attr; attr=tidyAttrNext(attr) ) {

				if(tidyAttrValue(attr))
				{
					//	printf("=@@@@@\"%s\" ",tidyAttrValue(attr));
					if(temp == 1)
					{
						csrftoken=tidyAttrValue(attr);
						//printf("In dumbnode function : token =  %s\n\n",csrftoken);
						temp=0;
					}  
					if(temp == 3)
					{
						attr=tidyAttrNext(attr);
						captcha=tidyAttrValue(attr);
						printf("In dumbnode function : Captcha =  %s\n\n",captcha);
						temp=0;
					}

					if(strcmp(tidyAttrValue(attr),"csrfmiddlewaretoken") == 0 )
					{
						temp = 1;
					}


					if(strcmp(tidyAttrValue(attr),"captcha_0") == 0 )
					{
						temp = 3;
					}
				}
			}  
		}
		dumpNode(doc, child, indent + 4); /* recursive */ 
	}
}

void captcha_image()
{

	char url_image[100];
	char filename[100];
	sprintf(url_image,"%scaptcha/image/%s",url,captcha);
	sprintf(filename,"%s",captcha);
	CURL *curl;
	FILE *pagefile;
	CURLcode res;
	curl = curl_easy_init();
	pagefile = fopen(filename, "w+");
	curl_easy_setopt(curl, CURLOPT_URL,url_image);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);
	printf("\n\nGET requst for Captcha\n\n");
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, pagefile);
	curl_easy_perform(curl);
	fclose(pagefile);
}


int main()
{
	unsigned char *buffer;
	FILE *outfile;
	char str[400];
	char *b1=(char *)malloc(500 *sizeof(char ));
	char *end;
	FILE *fp;
	outfile = fopen ("RDK_information.txt","r");
	if (outfile)
	{
		//printf("file opened\n");
		if (fgetc(outfile)!=EOF)
		{
			printf("\n\t\t\t******Registration already done(Need to do Authentication)********\n\n");
			fclose(outfile); 
		}
		buffer=auth_post();
		//printf("rrrr%s",buffer);
		end=auth_jsonparse(buffer);
		//printf("In main %s",end);
		socket_connection(end);
	}

	else
	{
		printf("\n\t\t\t\t*****Registration has to be done (NEW USER)**********\n\n");
		FILE *fp;
		getrequest();
		//printf("In main function : Captcha =  %s\n\n",captcha);
		captcha_image();
		buffer=post();
		//printf("in main function %s",buffer);
		jsonparse(buffer);
		b1=auth_post();
		end=auth_jsonparse(b1);
		socket_connection(end);
	}
	return 0;
}



