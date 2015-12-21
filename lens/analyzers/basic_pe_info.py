import pefile

class basic_pe_info:
    '''
    The analysis class must always have an attribute called self.yara_sigs.
    The attribute self.yara_sigs_exclude is a list of yara rules, that if the
    file matches, then this analysis module will not be used.
    A method called analyze with the parameters below.
    Finally, it must also be the only class in the .py file starting with
    analyzer_*
    '''
    def __init__(self):
        # yara_sigs is a list of yara rule names, associated with this analyzer
        # if these signatures match a file, this analyzer will be run
        self.yara_sigs = ['pefile']
        self.yara_sigs_exclude = []

    def analyze(self, filepath=None, filecontents=None):
        '''
        This function will analyze the file provided and provide output in json
        format.
        '''
        pedata = {}

        if filepath is not None:
            print 'working with file path'
            pe = pefile.PE(filepath)
        elif filecontents is not None:
            print 'use file contents'
            pe = pefile.PE(data=filecontents)
        else:
            return {}

        headerdata = {}
        sectiondata = {}
        try:
            # Get basic info
            headerdata['entryPoint'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            headerdata['baseAddress'] = hex(pe.OPTIONAL_HEADER.ImageBase)
            sectiondata['count'] = pe.FILE_HEADER.NumberOfSections
        except Exception, e:
            headerdata['error'] = str(e)

        try:
            # Get sections virtual and raw size
            for section in pe.sections:
                name = section.Name.replace('\x00','')
                sectiondata[name] = \
                    {'virtualAddress': hex(section.VirtualAddress),
                     'virtualSize': hex(section.Misc_VirtualSize),
                     'sizeOnDisk': section.SizeOfRawData}
        except Exception, e:
            sectiondata['error'] = str(e)

        # get imports
        importdata = {}
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                importdata[entry.dll] = []
                for imp in entry.imports:
                    importdata[entry.dll].append({'name': imp.name,
                                                  'address': hex(imp.address)})
        except AttributeError, e:
            importdata['none'] = 'none'
        except Exception, e:
            importdata['error'] = str(e)

        if 'none' in importdata.keys():
            importdata['count'] = 0
        else:
            importdata['count'] = sum(len(importdata[v]) for v in importdata.keys())

        # get exports
        exportdata = {}
        try:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exportdata[exp.name] = {'imageBase': pe.OPTIONAL_HEADER.ImageBase,
                                        'address': exp.address,
                                        'ordinal': exp.ordinal}
        except AttributeError, e:
            exportdata['none'] = 'none'
        except Exception, e:
            exportdata['error'] = str(e)

        if 'none' in exportdata.keys():
            exportdata['count'] = 0
        else:
            exportdata['count'] = sum(len(exportdata[v]) for v in exportdata.keys())

        pedata['header'] = headerdata
        pedata['sections'] = sectiondata
        pedata['imports'] = importdata
        pedata['exports'] = exportdata

        # get quick PE info
        '''
        pe = pefile.PE(filecontents, fast_load=True)
        pe.parse_data_directories( directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG'],
        #    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC'], # Do
        #    not parse relocations
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT'] ] )
        '''
        return pedata
