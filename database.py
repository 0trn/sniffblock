import os
import shutil

'''
def mkdir(directory):
    parent_dir = "/home/trn/sbp/sniffecure/sniffecure"
    path = os.path.join(parent_dir, directory) 
    os.makedirs(path) 
''' # linux

#'''
from os import mkdir
#''' # windows

class Group:
    def __init__(self, tablename = "center"):
        self.tablename = str(tablename)
        if not os.path.exists("./database/"+tablename+"/"):
            mkdir("./database/"+tablename+"/")

    def put(self, name, content=None):
        entry = open("./database/"+self.tablename+"/"+str(name), "w+")
        if content!=None:
            entry.write(str(content))
        entry.close()
        return self.get(name)

    def add(self, name, content=None):
        entry = open("./database/"+self.tablename+"/"+str(name), "a+")
        if content!=None:
            entry.write(str(content))
        entry.close()
        return self.get(name)

    def get(self, name):
        try:
            entry = open("./database/"+self.tablename+"/"+str(name), "r")
        except FileNotFoundError:
            return None;
        content = entry.read()
        entry.close()
        return content.strip()

    def delete(self, name):
        try:
            os.remove("./database/"+self.tablename+"/"+str(name))
        except FileNotFoundError:
            print("ERROR: "+"./database/"+self.tablename+"/"+str(name))
            return None;
        return self

    def destroy(self):
        shutil.rmtree('./database/'+self.tablename)
        return self
