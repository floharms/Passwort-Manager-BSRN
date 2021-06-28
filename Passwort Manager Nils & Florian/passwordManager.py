#für die Verschlüsselung verwendet:
import base64
from platform import uname
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
#verwendet für Hashing:
from passlib.context import CryptContext
#für das unklar machen von inputs verwendet
from getpass import getpass
#zum erstellen der Rückruffunktion (Callback function) verwendet:
from threading import Timer
#zum Erzeugen von Passwörtern verwendet:
import string
import secrets
#zur Bearbeitung der Zwischenablage verwendet:
from pyperclip import copy
#wird verwendet um das aktuelle Verzeichnis zu erhalten:
import os

#----------------------Hashing- und Verschlüsselungsfunktionen----------------------#

#Diese Hash Funktion wird verwendet, um plain text zu hashen und Hashes zu vergleichen
def hasher(mode, plainText, hashedPassword=None):
    # CryptContext mit dem richtigen Algorithmus Satz erzeugen 
    context = CryptContext(
            schemes=["pbkdf2_sha256"],
            default="pbkdf2_sha256",
            pbkdf2_sha256__default_rounds=100000
    )
    if mode == 'hash':
        return context.hash(plainText)
    elif mode == 'check':
        return context.verify(plainText, hashedPassword)

#generateKey benutzt eine Key Derivative Funktion um einen kryptografischen Schlüssel basierend auf einem gegebenen String zu erzeugen
def generateKey(master):
    #salt ist ein zufälliger Zeichensatz, der zur Sicherung des Schlüssels bei seiner Erstellung verwendet wird
    salt = b'H\x1d\tMg\xc9\xe3\xec\xbeU\xee\x03\xec\x18\xf1U'
    #kdf steht für Key Derivate Funktion
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    ) 
    #Rückgabe der Cryptographic Funktion
    return base64.urlsafe_b64encode(kdf.derive(master.encode()))

#----------------------Ui Funktionen----------------------#
#Diese Funktionen sind in erster Linie dafür da, die main() Funktion clean zu halten.

#seperates print Statement
def welcomeMessage():
    print(
'''
_________________________________

    Nils and Florian's Password Manager
_________________________________
''')

#Die Funktion empfängt die Benutzer Auswahl
def mainMenu():
    selection = input(
'''Please select one of the following program functions:
1 - Get a list of all services for which there is stored username and password
2 - Save a new service's username and password 
3 - Delete a saved service's username and password 
4 - Change master password
5 - Change login timeout duration
6 - Fetch a service's username and password
7 - Close program
Type your selection here: ''')
    return selection

#Diese Funktion holt eine Liste aller gespeicherten services und gibt die Titel aus
def showServiceList():
    print('List of stored services: ')
    #man braucht nur die Titel, sodass wir wir die Schlüssel aus dem Verzeichnis holen können, welches getStoredData() zurückgibt
    storedServices = getStoredData().keys() 
    for service in storedServices:
        #Da masterpw und time store auch in der Datei gespeichert sind, wollen wir diese Titel herausfiltern
        if service != 'Master' and service != 'TimerStore':
            print(f' - {service}')

#----------------------Utility Funktionen----------------------#

#Diese Funktion liest userData und gibt ein Verzeichnis in der Form {'title': 'username|encryptedPassword'} zurück 
def getStoredData():
    directory = os.path.dirname(os.path.realpath(__file__))
    file = open(directory +'/userData.txt', 'r')
    dataDictionary = {}
    for line in file:
        #jede Zeile hat die Form: 'title username|encryptedDassword' .split() teil die Strings auf, wenn ein Leerzeichen steht:' ' 
        if len(line.strip()) != 0:
            key, value = line.split()
            dataDictionary[key] = value
    #Rückgabe des Verzeichnisses
    return dataDictionary

#----------------------Call back Funktionen----------------------#
#Dies sind Funktionen, die nach einer bestimmten Zeit ausgeführt werden und dann aufgerufen werden 

#einfache Funktion, die dem angegebenen Array ein Element hinzufügt
def passwordTimeout(timeoutMessage):
    timeoutMessage.append('timeoutReached')

#leert die Zwischenablage
def clipboardTimeout():
    copy('')

#----------------------Main Programm Funktionen----------------------#

#Funktion zur Überprüfung des Master Passworts eines Benutzers
def logOn():
    #getpass() funktioniert wie input() aber der Benutzer kann nicht sehen, was er tippt
    userInput = getpass(prompt='Please enter the master password (characters typed will be hidden): ')
    #holt den gespeicherten Hash des Master Passworts
    storedHash = getStoredData()['Master']
    #Rückgabe des Vergleichs der Hashes des Master Passworts und der Benutzereingabe.
    #außerdem Rückgabe des Verschlüsselungs Schlüssels der durch die Benutzereingabe generiert wurde
    return hasher('check', userInput, storedHash), generateKey(userInput)
        
#ChangeMasterKey erlaubt dem Benutzer das Maser Passwort zu ändern
def changeMasterKey(timeoutMessage, encryptionKey):
    #den Benutzer veranlassen, das Kennwort zweimal einzugeben, um sicherzustellen, dass er das neue Kennwort korrekt eingegeben hat
    userInput = getpass(prompt='Please enter the new master password: ')
    checkUserInput = getpass(prompt='Please re-enter the new master password: ')
    #zuerst prüfen, ob der Benutzer in der Zeit die er für die Eingabe des neuen Passworts benötigt hat, kein Timeout hat
    if len(timeoutMessage) > 0:
        print('Error: Your session has timed out, you will need to log in again')
        return 'timeout'
    #wenn die beiden Passwörter identisch sind, dann den gespeicherten Hash des Master Passworts aktualisieren und alle Passwörter neu verschlüsseln
    elif userInput == checkUserInput:
        #holt das Verzeichnis der gespeicherten Daten
        storedData = getStoredData()
        #das Verzeichnis mit dem neuen Master Passwort Hash aktualisieren
        storedData['Master'] = hasher('hash', userInput)
        #alle Passwörter wieder verschlüsseln:
        newEncryptionKey = generateKey(userInput)
        fernetOldKey = Fernet(encryptionKey)
        fernetNewKey = Fernet(newEncryptionKey)
        for title in storedData.keys():
            if title != 'Master' and title != 'TimerStore':
                username, encryptedPassword = storedData[title].split('|')
                decryptedPassword =  fernetOldKey.decrypt(encryptedPassword.encode())
                newEncryptedPassword = fernetNewKey.encrypt(decryptedPassword).decode()
                storedData[title] = f'{username}|{newEncryptedPassword}'
        #Überschreiben der userData.txt Datei mit dem aktualisierten Verzeichnis 
        directory = os.path.dirname(os.path.realpath(__file__))
        with open(directory + '/userData.txt', 'w') as file:
            for key in storedData.keys():
                print(f'{key} {storedData[key]}\n', file=file)
        print('Master password successfully changed!')
        return newEncryptionKey
    #wenn die Passwörter nicht übereinstimmen, kehrt der Benutzer zum Hauptmenü zurück
    else:
        print('Error: Those passwords did not match')
        return None

#saveNewService erlaubt dem Benutzer, Benutzername und Passwörter zum System hinzuzufügen
def saveNewService(timeoutMessage, encryptionKey):
    #zuerst die Titel aller gespeicherten Services holen
    storedServices = getStoredData().keys()
    #Erstellt eine Schleife für den Benutzer der den Titel eingibt, die er nur verlassen kann, wenn er ein Timeout hat oder einen eindeutigen Titelnamen eingibt
    newServiceLoop = True
    while newServiceLoop:
        title = input('Please input the title of the new service you are adding: ')
        #prüfen dass der Benutzer kein Timeout hat
        if len(timeoutMessage) > 0:
            print('Error: Your session has timed out, you will need to log in again')
            return 'timeout'
        #prüfen ob der vom Benutzer eingegebene Titel nicht bereits gespeichert ist
        elif title in storedServices:
            print('Error: this service already exists')
        else:
            #Schleife unterbrechen, wenn der Titel eindeutig ist
            newServiceLoop = False
    #Erzeugen einer Schleife für die Eingabe des Benutzernamen
    newUsernameLoop = True
    while newUsernameLoop:
        username = input(f'Please input your username for {title}: ')
        #prüfen dass der Benutzer kein Timeout hat
        if len(timeoutMessage) > 0:
            print('Error: Your session has timed out, you will need to log in again')
            return 'timeout'
        #mit dem Benutzer prüfen, ob er mit dem eingegebenen Benutzernamen einverstanden ist
        confirm = input(f'Please confirm {username} is the correct username (y/n): ')
        #prüfen dass der Benutzer keine Timeout hat
        if len(timeoutMessage) > 0:
            print('Error: Your session has timed out, you will need to log in again')
            return 'timeout'
        #dann prüfen ob der Benutzer bestätigt hat und wenn ja, Schleife beenden
        elif confirm == 'y':
            print('Username confirmed!')
            newUsernameLoop = False
        else:
            print('Username confirm cancelled!')
    #eine Schleife für die Auswahl des Passworttyps erstellen
    passwordChoiceLoop = True
    while passwordChoiceLoop:
        #zunächst prüfen, ob der Benutzer sein eigenes Kennwort eingeben oder ein Kennwort generieren möchte
        generationChoice = input('Would you like your password generated by the program? (y/n): ')
        #prüfen dass der Benutzer kein Timeout hat
        if len(timeoutMessage) > 0:
            print('Error: Your session has timed out, you will need to log in again')
            return 'timeout'
        #die Schleife unterbrechen, wenn eine akzeptierte Antwort gegeben wurde
        elif generationChoice == 'y':
            print('Generate password selected')
            passwordChoiceLoop = False
        elif generationChoice == 'n':
            print('Create own password selected')
            passwordChoiceLoop = False
        #in der Schleife bleiben, wenn es keine gültige Antwort war
        else:
            print(f'"{generationChoice}" is not a valid answer')
    #Erstellen einer Schleife für die Erstellung des Passworts
    newPasswordLoop = True
    while newPasswordLoop:
        if generationChoice == 'n':
            #Wenn der Benutzer sein eigenes Kennwort eingeben möchte, muss er dasselbe Kennwort zweimal eingeben
            password = getpass(prompt=f'Please enter the password for {title}: ')
            checkPassword = getpass(prompt=f'Please re-enter the password for {title}: ')
            #prüfen dass der Benutzer kein Timeout hat
            if len(timeoutMessage) > 0:
                print('Error: Your session has timed out, you will need to log in again')
                return 'timeout'
            #Schleife nur unterbrechen, wenn die Kennwörter übereinstimmen
            elif password == checkPassword:
                newPasswordLoop = False
                print('Password Confirmed!')
            else:
                print('Error: Those passwords did not match')
        elif generationChoice == 'y':
            #Erstellen eines Strings mit allen möglichen Zeichen für die Verwendung im Passwort
            alphabet = string.ascii_letters + string.digits + '@._()!'
            #32 zufällige Zeichen aus dem Alphabet auswählen, die im Kennwort verwendet werden sollen 
            password = ''.join(secrets.choice(alphabet) for _ in range(32))
            print('Your password has been generated!')
            newPasswordLoop = False
    #Nachdem das Passwort erhalten wurde, ob es generiert wurde oder vom Benutzer erstellt wurde, soll es verschlüsselt werden
    #ein Fernet Object mit dem encryptionKey erstellen, den wir vorher generiert haben
    fernet = Fernet(encryptionKey)
    #das Passwort mit Fernet verschlüsseln
    #.encode() and .decode() sind python Funktionen die verwendet werden, damit Fernet mit dem Passwort String arbeiten kann
    encryptedPassword = fernet.encrypt(password.encode()).decode()
    #Kombiniert Titel, Benutzername und Verschlüsseltes Passwort zu einem String und speichert ihn in der userData Datei
    directory = os.path.dirname(os.path.realpath(__file__))
    with open(directory + '/userData.txt', 'a') as file:
        print(f'{title} {username}|{encryptedPassword}\n', file=file)
    print('Password encrypted, and new service saved to local storage!')
    print('You will now be taken back to the main menu')

#Die Funktion erlaubt es dem Benutzer die Dauer des Anmelde Timeouts zu ändern
def changeLoginTimout(timeoutTimer, timeoutMessage):
    #Zuerst eine Schleife erstellen
    timeoutChoice = True
    while timeoutChoice:
        #dann die Dauer in Minuten erhalten, welche der Benutzer die Timeout Zeit haben möchte
        newTimeout = input('Please type the number of minutes you would like the logout timer to be: ')
        #prüfen, ob der Benutzer ein Timeout hat
        if len(timeoutMessage) > 0:
            print('Error: Your session has timed out, you will need to log in again')
            return 'timeout'
        #prüfen dass der Benutzer einen integer Wert eingegeben hat
        isInteger = False
        try:
            newTimeout = int(newTimeout)
            isInteger = True
        except:
            print('You must enter an integer!')
        if isInteger:
            #Wenn ein integer Wert eingegeben wurde, prüfen, ob der Timeout zwischen 5 Minuten und 3 Stunden liegt
            if newTimeout < 5 or newTimeout > 180:
                print('Please pick a time between 5 and 180 minutes.')
            else:
                #wenn sie eine gültige Eingabe gemacht haben, den alten Timer löschen und den neuen erstellen
                timeoutTimer.cancel()
                timeoutMessage = []
                #den lokalen Speicher aktualisieren, um die Änderung der Timeout Dauer zu berücksichtigen
                storedData = getStoredData()
                storedData['TimerStore'] = newTimeout
                directory = os.path.dirname(os.path.realpath(__file__))
                with open(directory + '/userData.txt', 'w') as file:
                    for key in storedData.keys():
                        print(f'{key} {storedData[key]}\n', file=file)
                print('Timeout duration changed!')
                #Das neue Timeout Objekt zurückgeben und gleichzeitg auch nennen 
                return Timer(newTimeout*60, lambda: passwordTimeout(timeoutMessage))

#Mit der Funktion kann der Benutzer einen gespeicherten Service löschen 
def deleteService(timeoutMessage):
    #dem Benutzer zunächst die zur Auswahl stehenden Services anzeigen 
    showServiceList()
    choice = input('Please enter the title of the service you want to remove: ')
    #prüfen ob der Benutzer ein Timeout hat
    if len(timeoutMessage) > 0:
        print('Error: Your session has timed out, you will need to log in again')
        return 'timeout'
    #alle Service Titel in eine Liste laden
    storedData = getStoredData()
    storedTitles = [key for key in storedData.keys() if key != 'Master' and key !='TimerStore']
    #prüfen, ob die Auswahl des Benutzers in der Liste der Titel enthalten ist
    if choice in storedTitles:
        #wenn die Auswahl in der Liste gefunden wird, aus dem Verzeichnis entfernen
        storedData.pop(choice)
        storedTitles.pop(storedTitles.index(choice))
        #dann die userData.txt Datei mit den aktualisierten Daten überschreiben
        directory = os.path.dirname(os.path.realpath(__file__))
        with open(directory + '/userData.txt', 'w') as file:
            for key in storedData.keys():
                if key != choice:
                    print(f'{key} {storedData[key]}\n', file=file)
        print(f'{choice} has been removed from the system')
    else:
        #wenn der Benutzer keine gültige Eingabe gemacht hat, kehrt er zum Hauptmenü zurück 
        print(f'{choice} is not an option, you will now be taken to the main menu')

#mit dieser Funktion kann der Benutzer Benutzernamen und Passwörter abrufen
def fetchServiceDetails(timeoutMessage, encryptionKey):
    #dem Benutzer zunächst zeigen, was er zur Auswahl hat
    showServiceList()
    #erhalte dann die Auswahl des Benutzers
    choice = input('Please enter the title of the service you want to view: ')
    #prüfen ob der Benutzer ein Timeout hat
    if len(timeoutMessage) > 0:
        print('Error: Your session has timed out, you will need to log in again')
        return 'timeout'
    #eine Liste aller Titel erhalten, aus denen der Benutzer wählen kann
    storedData = getStoredData()
    storedTitles = [key for key in storedData.keys() if key != 'Master' and key !='TimerStore']
    if choice in storedTitles:
        #Benutzernamen und Passwort aufteilen, mithilfe von einem: '|' 
        username, encryptedPassword = storedData[choice].split('|')
        #Ein Fernet Objekt erstellen, mit dem Verschlüsselungs Key abgeleitet vom Master Passwort
        fernet = Fernet(encryptionKey)
        #Das Passwort mithilfe des Fernet Objekts entschlüsseln
        decryptedPassword =  fernet.decrypt(encryptedPassword.encode()).decode()
        #das entschlüsselte Passwort in die Zwischenablage kopieren
        copy(decryptedPassword)
        #Zwischenablage so einstellen, dass sie in 60 Sekunden gelöscht wird
        clipboardTimer = Timer(60,  clipboardTimeout)
        clipboardTimer.start()
        #den Benutzer über den Benutzernamen des gewählten Services informieren und auch darüber, dass das Passwort für die nächste Miute in seiner Zwischenablage sein wird
        print(f'Your username for {choice} is: {username}, and your password has been coppied to the clipboard where it will remain for 1 minute.')
        return clipboardTimer
    else:
        #wenn die Auswahl nicht gültig war, darüber informieren und zum Hauptmenü zurück gehen
        print(f'{choice} is not an option, you will now be taken to the main menu')
        return None
    
#Main Funktion:
def main():
    #die Welcome Message soll nur einmal angezeigt werden, also rufen wir sie außerhalb der "laufenden" Schleife auf
    welcomeMessage()
    clipboardUsed = False
    running = True
    while running:
        #Der Benutzer bleibt in der Anmeldeschleife hängen, bis er das richtige Master Passwort eingegeben hat
        logOnLoop = True
        while logOnLoop:
            valid, encryptionKey = logOn()
            if valid:
                logOnLoop = False
                print('Welcome Back!')
            else:
                print('Error: That is not the correct password')
        #der gespeicherte Timeout wird lokal gespeichert, da der Benutzer die Dauer bearbeiten kann
        storedTimeout = int(getStoredData()['TimerStore'])*60
        timeoutMessage = []
        #Timer wird mit passwordTimeout (timeoutMessage) laufen, nach einer Dauer von storedTimeout
        #lambda erlaubt es, Argumente für die angegebene Funktion zu parsen, ohne dass sie läuft
        timeoutTimer = Timer(storedTimeout, lambda: passwordTimeout(timeoutMessage))
        timeoutTimer.start()
        #Die Hauptschleife lässt den Benutzer zum Hauptmenü zurückkehren, bis er ein timeout eintritt oder er das Programm schließt
        mainLoop = True
        while mainLoop:
            #Wahl des Benutzers erhalten
            selection = mainMenu()
            #wenn der Benutzer noch kein Timeout hat, die ausgewählte Funktion ausführen
            #Timeout Meldung muss nur an Funktionen übergeben werden, bei denen der Benutzer eine Auswahl trifft
            if selection == '1' and len(timeoutMessage) == 0:
                showServiceList()
            elif selection == '2' and len(timeoutMessage) == 0:
                selection = saveNewService(timeoutMessage, encryptionKey)
            elif selection == '3' and len(timeoutMessage) == 0:
                selection = deleteService(timeoutMessage)
            elif selection == '4' and len(timeoutMessage) == 0:
                selection = changeMasterKey(timeoutMessage, encryptionKey)
                if selection != 'timeout' and selection != None:
                    encryptionKey = selection
            elif selection == '5' and len(timeoutMessage) == 0:
                selection = changeLoginTimout(timeoutTimer, timeoutMessage)
                if selection != 'timeout':
                    #wenn Timeout nicht zurückgegeben wurde, wurde der neue Timeout Timer zurückgegeben
                    timeoutTimer = selection
                    timeoutTimer.start()
            elif selection == '6' and len(timeoutMessage) == 0:
                selection = fetchServiceDetails(timeoutMessage, encryptionKey)
                #wenn weder timeout noch None zurückgegeben wurde, wurde das Timer Objekt zurückgegeben
                if selection != 'timeout' and selection != None:
                    clipboardUsed = True
                    clipboardTimer = selection
            elif selection == '7':
                print('Closing program')
                #das Programm wird erst beendet, wenn alle Timer abgelaufen sind, wir müssen sie also abbrechen
                timeoutTimer.cancel()
                if clipboardUsed == True:
                    if clipboardTimer.is_alive():
                        copy('')
                        clipboardTimer.cancel()
                #Sowohl die Main Schleife als auch die running Schleife auf false setzen, damit das Programm zu Ende läuft
                mainLoop = False
                running = False
            #dies wird ausgeführt, wenn der Benutzer nach dem Timeout eine ungültige Auswahl eingibt 
            elif len(timeoutMessage) > 0:
                print('Error: Your session has timed out, you will need to log in again')
                #Setzen der Main Schleife auf false bedeutet, dass die Log-On-Schleife neu gestartet wird
                mainLoop = False
            else:
                print(f'Error: "{selection}"" is not a valid input')
            #dies wird ausgeführt, wenn der Benutzer in einer der Main Funktionen eine timeout hat
            if selection == 'timeout':
                #Setzen der Main Schleife auf false bedeutet, dass die Log-On-Schleife neu gestartet wird
                mainLoop = False

#Diese Anweisung ruft die Main Funktion auf, wenn das Programm zum ersten Mal ausgeführt wird
if __name__ == '__main__':
    main()
