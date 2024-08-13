#!/usr/bin/python3

#Coded by: L4med
#Github: https://github.com/L4med
#Description:
    # A basic web scraper script and data collector to exctract data from web pages in an automated way.


import os
import webbrowser
import requests
import argparse
import threading
import time
import itertools
import sys
import asyncio
from bs4 import BeautifulSoup, element
import colorama
from colorama import Fore

#-----------Definición de variables globales-----------
versiones_encontradas = []

#---------------Definición de funciones----------------
#
#
#----------------Hacer petición----------------
def hacerRequestPost(a,b):
    auth_data = {'a':a, 'b': b}
    r = requests.post(str(args.url), data=auth_data)
    return r

#--------------Cambiar User-Agent--------------
def cambiarUserAgent(url, user_agent):
    headers = {
        'User-Agent': user_agent
    }
    response = requests.get(url, headers=headers) 
    return response  

#----------------Buscar palabras--------------
def buscar_palabras(texto, cadena):
    palabras = texto.split()
    palabras_encontradas = []
    for palabra in palabras:
        if palabra.lower().startswith(cadena.lower()):
            palabras_encontradas.append(palabra)
    return palabras_encontradas   
    
    
#----------------Mostrar petición--------------
def mostrarRequest(request):
    print("Puerto: " + str(args.puerto))
    print("Respuesta: " + str(request.history))
    print("Código HTTP: " + str(request.status_code))
    print("Dirección URL: " + request.url)
    print("Cabeceras: " + str(request.headers))

#---------Mostrar cabeceras interesantes-------
def mostrarCabecerasInteresantes(r):
    print(Fore.CYAN + '\n---------------CABECERAS INTERESANTES---------------')  
    if r.headers.get('Server') != None:      
        print('[*]Servidor: ' + str(r.headers.get('Server')))
        versiones_encontradas.append(r.headers.get('Server'))  
    if r.headers.get('X-Powered-By') != None:
        print('[*]X-Powered By: ' + str(r.headers.get('X-Powered-By')))
        versiones_encontradas.append(r.headers.get('X-Powered-By')) 
    if r.headers.get('Host-Header') != None:
        print('[*]Host-Header: ' + str(r.headers.get('Host-Header')))
        versiones_encontradas.append(r.headers.get('Host-Header')) 
    if r.headers.get('X-Served-By') != None:
        print('[*]X-Served-By: ' + str(r.headers.get('X-Served-By')))
        versiones_encontradas.append(r.headers.get('X-Served-By')) 
    if r.headers.get('X-Generator') != None:
        print('[*]X-Generator: ' + str(r.headers.get('X-Generator')))
        versiones_encontradas.append(r.headers.get('X-Generator')) 
    if r.headers.get('Acces-Control-Allow-Credentials') != None:
        print('[*]Acces-Control-Allow-Credentials: ' + str(r.headers.get('Acces-Control-Allow-Credentials')))
 
#----------------Mostrar información del servidor--------------        
def mostrarInformacionServidor(r):
    soup = BeautifulSoup(r.text, "html.parser")
    print(Fore.CYAN + '\n---------------INFORMACIÓN DEL SERVIDOR---------------')  
    servidor = soup.find('meta', {'name': 'generator'})        
    if servidor:
        print(servidor['content'])
    else:
        print("[*]Información del servidor: No se encontró información")
  
#----------------Mostrar versiones del servidor--------------          
def mostrarVersiones(r):
    soup = BeautifulSoup(r.text, "html.parser")
    print(Fore.CYAN + '\n---------------VERSIONES DEL SERVIDOR---------------')
    versiones = soup.find_all('meta', attrs={'name': 'generator'})           
    if versiones:
        for version in versiones:
            print('[*]', end='')
            print(version['content'])   
            versiones_encontradas.append(version['content'])          
    else:
        print("[*]No se encontraron versiones del servidor")    

#----------------Mostrar palabras interesantes--------------
def mostrarPalabrasClave(r,palabras_clave,texto):
    contenido = r.text.lower()
    print(texto)
    for palabra in palabras_clave:
        if palabra in contenido:
            print(palabra)
        
#----------------Mostrar comentarios----------------    
def mostrarComentarios(r):
    soup = BeautifulSoup(r.text, "html.parser")
    print(Fore.CYAN + '\n---------------Comentarios---------------')
    texto = soup.find_all(string = lambda text:isinstance(text,element.Comment))
    print('[*]Número de comentarios encontrados: ' + str(len(texto)))
    y=1
    for x in texto:
        print('[' + str(y) + ']', end='')
        print(x)
        y=y+1
        
#----------------Mostrar comentarios interesantes--------------        
def mostrarComentariosInteresantes(r):
    soup = BeautifulSoup(r.text, "html.parser")
    print(Fore.CYAN + '\n---------------COMENTARIOS RELACIONADOS CON VERSIONES---------------')
    texto = soup.find_all(string = lambda text:isinstance(text,element.Comment))
    print('[*]Número de comentarios encontrados: ' + str(len(texto)))              
    y=1
    for x in texto:
        if 'version' or 'plugin' or 'v' in x:
            if any(chr.isdigit() for chr in x):
                print('[' + str(y) + ']', end='')
                print(x)                    
                #data_into_list = x.split(" ")
                #for palabras in data_into_list:
                    #print(palabras)                        
        y=y+1
        
#----------------Mostrar enlaces----------------    
def mostrarEnlaces(r):
    soup = BeautifulSoup(r.text, "html.parser")
    print(Fore.CYAN + '\n-----------------Enlaces-----------------')
    url1 = r.url
    page = requests.get(url1)
    for href in soup.find_all('a',href=True):
        print(href.get('href'))   
        
#----------------Mostrar plugins----------------         
def mostrarPlugins(r):
    soup = BeautifulSoup(r.text, "html.parser")
    print(Fore.CYAN + '\n---------------PLUGINS---------------')
    plugins = soup.find_all('link', {'rel': 'plugin'})
    for plugin in plugins:
        print('[*]', end='')
        print(plugin.get('href'))
    if plugins:
        for plugin in plugins:
            print("[*]Plugin:", plugin.get('href'))
    else:
        print("[*]No se encontraron plugins")

#----------------Mostrar plugins por hojas----------------         
def mostrarPluginsPorHojas(r):
    soup = BeautifulSoup(r.text, "html.parser")
    print(Fore.CYAN + '\n---------------PLUGINS EN BASE A HOJAS DE ESTILO---------------')
    plugins = soup.find_all('link', {'rel': 'stylesheet'})
    print("Posibles plugins por hojas de estilo:")
    if plugins:
        for plugin in plugins:
            print("[*]Plugin:", plugin.get('href'))
    else:
        print("[*]No se encontraron plugins relacionados por hojas de estilo")

#----------------Comprobar JavaScript----------------  
def existeJS(r):
    soup = BeautifulSoup(r.text, "html.parser")
    print(Fore.CYAN + '\n---------------JAVASCRIPT---------------')
    javascript = False       
    for script in soup.find_all("script"):
        if "jquery" in str(script).lower():
            javascript = True
            break
    if javascript:
        print("[*]Javascript: Detectado") 
    else: 
        print ("[*]Javascript: No detectado")

#----------------Hacer fuzz----------------        
def fuzz(diccionario,url):
    archivo_passwords = open(diccionario, "r")
    data = archivo_passwords.read()
    data_into_list = data.split("\n")
    for passwords in data_into_list:
        time.sleep(args.delay)
        r = requests.get(url+ '/' + passwords)
        if(str(r.status_code) != '404'):
            print('\nDirección URL: ' + r.url + '\nCódigo HTTP: ' + str(r.status_code))                
    archivo_passwords.close()     

#------------------------------------
def mostrarCve(soft):    
    if any(chr.isdigit() for chr in soft):
        r = requests.get("https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=" + soft)          
        contenido = r.text.lower()
        texto=contenido
        cadena_buscada = 'href="/cgi-bin/cvename.cgi?name=cve-20'
        resultado = buscar_palabras(texto, cadena_buscada)
        comilla= '"'
        if resultado:
            print("\n[+]CVE encontrados: ")
            for palabra in resultado:
                if palabra[32:46].find(comilla) != -1:               
                    print(palabra[32:45])
                else:
                    print(palabra[32:46])
        else:
            print("\nNo se encontraron CVE")
    else:
        print('No se ha encontrado la versión concreta de '+soft)                 
    
        
#----------------Carga----------------    
def animate():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done:
            break
        sys.stdout.write('\rLoading ' + c)
        sys.stdout.flush()
        time.sleep(0.1)

#----------------Temporizador--------------
def tiempo():
    fin = False
    time.sleep(15)
    fin = True
    if fin == True and args.fuzzer != 0:
        print(Fore.RED + '\n[*]Tiempo excedido en la solicutud')        
        os._exit(1)
                                   
#       
#----------------Definición de argumentos----------------
#

parser = argparse.ArgumentParser()
parser.add_argument('-u', '--url', help="Introducir una URL", type=str, required=True)
parser.add_argument('-p', '--puerto', help="Seleccionar puerto distinto", type=int, default=443)
parser.add_argument('-g', '--user_agent', help="Cambiar User-Agent", default='User-Agent', type=str)
parser.add_argument('-a', '--all', help="Mostrar toda la información posible", nargs='?', const=1, default=0)
parser.add_argument('-c', '--comentario', help="Mostrar comentarios de la web", nargs='?', const=1, default=0)
parser.add_argument('-e', '--enlaces', help="Mostrar enlaces de la web", nargs='?', const=1, default=0)
parser.add_argument('-k', '--cabeceras_interesantes', help="Mostrar cabeceras interesantes", nargs='?', const=1, default=0)
parser.add_argument('-b', '--comentarios_interesantes', help="Mostrar comentarios relacionados con las versiones", nargs='?', const=1, default=0)
parser.add_argument('-i', '--informacion_servidor', help="Mostrar información del servidor", nargs='?', const=1, default=0)
parser.add_argument('-v', '--versiones', help="Mostrar versiones del servidor", nargs='?', const=1, default=0)
parser.add_argument('-m', '--cms', help="Mostrar posibles CMS", nargs='?', const=1, default=0)
parser.add_argument('-l', '--plugins', help="Mostrar plugins", nargs='?', const=1, default=0)
parser.add_argument('-j', '--javascript', help="Comprobar si existe JavaScript", nargs='?', const=1, default=0)
parser.add_argument('-f', '--fuzzer', help="Ejecutar fuzzer", nargs='?', const=1, default=0)
parser.add_argument('-d', '--delay', help="Delay para fuzzer", type=int, default=0)
parser.add_argument('-t', '--cve', help="Mostrar posibles CVEs", nargs='?', const=1, default=0)
args=parser.parse_args()

colorama.init(autoreset=True)
#       
#----------------Comprobar argumentos----------------
#

if(args.comentario != 1 and args.comentario != 0):
    print(Fore.RED + 'Argumento comentario no válido')

elif(args.enlaces != 1 and args.enlaces != 0):
    print(Fore.RED + 'Argumento enlaces no válido')
    
elif(args.cabeceras_interesantes != 1 and args.cabeceras_interesantes != 0):
    print(Fore.RED + 'Argumento cabeceras no válido')

elif(args.comentarios_interesantes != 1 and args.comentarios_interesantes != 0):
    print(Fore.RED + 'Argumento comentarios no válido')
    
elif(args.informacion_servidor != 1 and args.informacion_servidor != 0):
    print(Fore.RED + 'Argumento informacion_servidor no válido')
    
elif(args.versiones != 1 and args.versiones != 0):
    print(Fore.RED + 'Argumento versiones no válido')
    
elif(args.cms != 1 and args.cms != 0):
    print(Fore.RED + 'Argumento cms no válido')
    
elif(args.plugins != 1 and args.plugins != 0):
    print(Fore.RED + 'Argumento plugins no válido')
    
elif(args.javascript != 1 and args.javascript != 0):
    print(Fore.RED + 'Argumento javascript no válido')
    
elif(args.cve != 1 and args.cve != 0):
    print(Fore.RED + 'Argumento test no válido')   
    
elif(args.all != 1 and args.all != 0):
    print(Fore.RED + 'Argumento all no válido')                   
      
else:

#       
#----------------Empezar funciones----------------
#

    done = False
    t = threading.Thread(target=animate)
    t.start()
    if(args.fuzzer == 0):
        t2 = threading.Thread(target=tiempo)
        t2.start()
    #cabeceras = {'': ''}
    #r = requests.get(args.url, headers=cabeceras)
    #r = requests.get(args.url + ":" + str(args.puerto)) 
    try:
        if(args.user_agent != 'User-Agent'):
            r = cambiarUserAgent(args.url, args.user_agent)          
        else:
            r = requests.get(args.url)
    except requests.exceptions.RequestException as e:
        print(Fore.RED + "\n[*]Error al conectar: ",e)
    try:        
        soup = BeautifulSoup(r.text, "html.parser")
        print(Fore.CYAN + "\n---------------Respuesta---------------")
        mostrarRequest(r)
    #archivo = open('html.html', "r")
    

#----------------Ver todo----------------
        if(args.all == 1):      
            args.cabeceras_interesantes = 1
            args.comentarios_interesantes = 1
            args.informacion_servidor = 1
            args.versiones = 1
            args.cms = 1
            args.plugins = 1
            args.javascript = 1 
                      
#----------------Ver comentarios----------------
        if(args.comentario == 1):
            mostrarComentarios(r)          

#----------------Ver cabeceras interesantes----------------
        if(args.cabeceras_interesantes == 1):       
            mostrarCabecerasInteresantes(r)  

#----------------Ver información del servidor----------------                   
        if(args.informacion_servidor == 1):       
            mostrarInformacionServidor(r)  

#----------------Ver versiones----------------        
        if(args.versiones == 1):        
            mostrarVersiones(r)    
            
#----------------MOstrar CVEs----------------             
        if (args.cve == 1): 
            mostrarCabecerasInteresantes(r) 
            mostrarInformacionServidor(r)  
            mostrarVersiones(r)
            print(Fore.CYAN + '\n---------------CVEs---------------')                    
            for x in versiones_encontradas:   
                print("[*]CVEs para " +x + ":")     
                mostrarCve(x)                

#----------------Ver cms----------------            
        if(args.cms == 1):       
            print(Fore.CYAN + "\n---------------SISTEMA DE GESTIÓN DE CONTENIDOS---------------")
            palabras_clave = ["wordpress", "typo3", "joomla", "drupal", "contao", "neos", "adobe"]
            mostrarPalabrasClave(r,palabras_clave, "\nPosibles CMS: ")         

#----------------Ver comentarios interesantes----------------        
        if(args.comentarios_interesantes == 1):      
            mostrarComentariosInteresantes(r)         

#----------------Ver plugins----------------        
        if(args.plugins == 1):      
            mostrarPlugins(r)
            mostrarPluginsPorHojas(r)  

#----------------Existe JavaScript----------------        
        if(args.javascript == 1):        
            existeJS(r)           
              
#----------------Ver enlaces----------------
        if(args.enlaces == 1):
            mostrarEnlaces(r)  
            
#----------------Hacer fuzz----------------    
        if(args.fuzzer != 0):
            if(args.fuzzer == 1):
                fuzz("/usr/share/wordlists/dirb/common.txt",args.url) 
            else:
                fuzz(args.fuzzer,args.url)

    except:
        print(Fore.RED + "[*]Cancelado por el usuario")
    
done = True    
os._exit(1)

