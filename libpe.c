#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "libpe/pe.h"
//#include "libpe/fuzzy.h"
#include "libpe/exports.h"
#include "libpe/hashes.h"
#include "libpe/imports.h"
#include "libpe/misc.h"
#include "libpe/peres.h"

int main(void) {
	pe_ctx_t ctx;
	pe_err_e err = pe_load_file(&ctx, "idag.exe");
	if (err != LIBPE_E_OK) {
		return EXIT_FAILURE;
	}

	err = pe_parse(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

	if (!pe_is_pe(&ctx)) {
		return EXIT_FAILURE;
	}


	printf("Get Header Hashes \n \n");
	pe_hdr_t header_hashes = get_headers_hash(&ctx);
	printf("DOS : md5 : %s \n", header_hashes.dos.md5);
	printf("DOS : sha1 : %s \n", header_hashes.dos.sha1);
	printf("DOS : sha256 : %s \n", header_hashes.dos.sha256);
	printf("DOS : ssdeep : %s \n", header_hashes.dos.ssdeep);
	printf("COFF : md5 : %s \n", header_hashes.coff.md5);
	printf("COFF : sha1 : %s \n", header_hashes.coff.sha1);
	printf("COFF : sha256 : %s \n", header_hashes.coff.sha256);
	printf("COFF : ssdeep : %s \n", header_hashes.coff.ssdeep);
	printf("Optional : md5 : %s \n", header_hashes.optional.md5);
	printf("Optional : sha1 : %s \n", header_hashes.optional.sha1);
	printf("Optional : sha256 : %s \n", header_hashes.optional.sha256);
	printf("Optional : ssdeep: %s \n", header_hashes.optional.ssdeep); 
	// dealloc
	dealloc_hdr_hashes(header_hashes);


	printf("Get Section Hashes \n \n");
	pe_hash_section_t sections_hash = get_sections_hash(&ctx);
	IMAGE_SECTION_HEADER ** const sections = pe_sections(&ctx);
	int count = sections_hash.count;
	pe_hash_t *sample1 = sections_hash.sections;
	for ( int i=0; i<count; i++) {
		printf("Section name : %s \n", sample1[i].name); 
		printf("Sections md5 hash : %s \n", sample1[i].md5);
		printf("sections sha1 hash : %s \n", sample1[i].sha1);
		printf("secions ssdeep hash : %s \n", sample1[i].ssdeep);
	}
	// dealloc 
	dealloc_sections_hashes(sections_hash);	


	printf("Get File Hash \n \n");
	pe_hash_t filehash = get_file_hash(&ctx);
	printf("%s  \n", filehash.name);
	printf("%s  \n", filehash.md5);
	printf("%s  \n", filehash.sha1);
	printf("%s  \n", filehash.sha256);
	printf("%s \n", filehash.ssdeep);
	// dealloc
	dealloc_filehash(filehash);
	

	printf("Get imports \n \n");
	pe_import_t import_sample = get_imports(&ctx);
	printf("\n from C bind %d ",import_sample.dll_count); 
	for (int i=0; i<import_sample.dll_count; i++) {	
		printf("DLL NAME : %s \n", import_sample.dllNames[i]);
		for (int j=0; j<import_sample.functions[i].count; j++) {
			printf("\t Function name : %s \n", import_sample.functions[i].functions[j]);
		}
	}
	// dealloc
	dealloc_imports(import_sample);
	

	printf(" Entrophy : %f \n", pe_calculate_entropy_file(&ctx));


	// FPU trick
	if (pe_fpu_trick(&ctx)) 
		printf("true");
	else 
		printf("false");

	//CPL analysis
	printf("CPL analysis %d \n",pe_get_cpl_analysis(&ctx));
	
	// Check Fake Entrypoint
	printf("checkout fake entrypoint : %d \n", pe_has_fake_entrypoint(&ctx));

	// TLS Call Back info
	printf("TLS INFO : %d \n", pe_get_tls_callback(&ctx));

	printf("Get Exports \n \n");
  pe_exports_t exports = get_exports(&ctx);
		//int exports_functions = get_exports_functions_count(&ctx);
 		exports_t *sample = exports.exports;
		int exports_functions = exports.functions_count;
		if(exports.err != LIBPE_E_OK) {
			printf("cannot get exports ");
		}
		else{
		if (exports_functions == 0) printf(" No exports \n");
		for (int i=0; i<exports_functions; i++) {
		printf(" ADDR : %d     ", sample[i].addr);
		printf(" Function name %s \n",sample[i].function_name);
		}
 }
  // dealloc
	pe_dealloc_exports(exports);


	printf("Get Resources \n \n ");
	pe_resources_count_t count_res = get_resources_count(&ctx);
	printf("%d \n", count_res.resourcesDirectory);
	printf("%d \n", count_res.directoryEntry);
	printf("%d \n", count_res.dataString);
	printf("%d \n", count_res.dataEntry);

	pe_final_output_t resources = get_resources(&ctx);
	for( int i=0; i<count_res.resourcesDirectory; i++) {
				printf("NodeType : %d \n", resources.resourcesDirectory[i].NodeType);
				printf("Characteristics : %d \n", resources.resourcesDirectory[i].Characteristics);
				printf("TimeDateStamp : %d \n", resources.resourcesDirectory[i].TimeDateStamp);
				printf("MajorVersion : %d \n", resources.resourcesDirectory[i].MajorVersion);
				printf("MinorVersion : %d \n", resources.resourcesDirectory[i].MinorVersion);
				printf("NumberOfNamedEntries : %d \n",resources.resourcesDirectory[i].NumberOfNamedEntries);
				printf("NumberOfIdEntries : %d \n",resources.resourcesDirectory[i].NumberOfIdEntries);
		}	

for( int i=0; i<count_res.directoryEntry; i++) {
				printf("NodeType : %d \n", resources.directoryEntry[i].NodeType);
				printf("NameOffset : %d \n", resources.directoryEntry[i].NameOffset);
				printf("NameIsString : %d \n", resources.directoryEntry[i].NameIsString);
				printf("OffsetIsDirectory : %d \n", resources.directoryEntry[i].OffsetIsDirectory);
				printf("DataIsDirectory : %d \n", resources.directoryEntry[i].DataIsDirectory);
		}

	for( int i=0; i<count_res.dataString; i++) {
				printf("NodeType : %d \n", resources.dataString[i].NodeType);
				printf("Strlen : %d \n", resources.dataString[i].Strlen);
				printf("Size : %d \n", resources.dataString[i].String);
		}

	for( int i=0; i<count_res.dataEntry; i++) {
				printf("NodeType : %d \n", resources.dataEntry[i].NodeType);
				printf("OffsetToData : %d \n", resources.dataEntry[i].OffsetToData);
				printf("Size : %d \n", resources.dataEntry[i].Size);
				printf("CodePage : %d \n", resources.dataEntry[i].CodePage);
				printf("Reserved : %d \n", resources.dataEntry[i].Reserved);
		}
	// dealloc
  pe_dealloc_peres(&resources);

	printf("get imphash \n \n");
	char *output = imphash(&ctx, 2);
	printf("%s \n",output);

	// free
	err = pe_unload(&ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return EXIT_FAILURE;
	}

return 0;	
}
