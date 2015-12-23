
# http://stackoverflow.com/questions/6804582/extract-strings-from-a-binary-file-in-python


class analyzer_strings:
    '''
    The analysis class must always have an attribute called self.yara_sigs
    and a method called analyze with the parameters below.
    Finally, it must also be the only class in the .py file starting with
    analyzer_*
    '''
    def __init__(self):
        # yara_sigs is a list of yara rule names, associated with this analyzer
        # if these signatures match a file, this analyzer will be run
        self.yara_sigs = ['file']

    def analyze(self, filepath=None, filecontents=None):
        '''
        This function will analyze the file provided and provide output as a
        dictionary.
        '''
        results = {}
        return results

class helper:
    def __init__(self):
        print 'some stuff'

    def anotherfunction(self, stuff):
        print stuff
