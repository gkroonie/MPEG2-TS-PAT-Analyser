//MPEG2 Transport Stream Interrogator - PAT Printer Variation
//Written By George Kroon
#include "pch.h"
#include <stdio.h>
#include <stdlib.h>



//The following line disables some deprecation warnings I was getting.
#pragma warning(disable : 4996)
#define PID_LENGTH 188

//Global Variables.
FILE *ts_file;
int bytes_read;
char byte_in;
int pid_cnt = 0;
char pid_in[PID_LENGTH];
float pat_cnt = 0;
float pmt_cnt = 0;
float pat_perc;
float pmt_perc;
int pid_number;
unsigned char ts_id;
int version_number;
short int section_length;
int PCR_pid;
int es_number;
int pids[1000];
int unique = 0;
int unique_cnt = 0;
short int section_syntax_indicator;
short int zero;
int reserved1;
int reserved2;
int reserved3;
int current_next_indicator;
short int section_number;
short int last_section_number;
int for_loop_number;
int CRC_32;
short int program_number;
short int pmt_pid;
int pat_max;
short int network_pid;
char file_name[50];
char continue_program = 'y';
float file_length;
float flength_MB;
short int pointer_field;
unsigned short int table_id;
char sync_byte;
short int transport_error_indicator;
int transport_error_cnt = 0;
float error_perc;
short int payload_unit_start_indicator;
short int transport_priority;
int priority_cnt = 0;
short int transport_scrambling_control;
short int adaptation_field_control;
char continuity_counter;
char cc_cnt = 0;
int cc_error;





/*Void function (not returning anything) to print out an example Programme Association Table.
Called in "int main", after working out the relevant figures. Removing the "if" statement
surrounding the printf functions will print all of the PATs. */
void PATsection(void) {

	//Bitwise operations to find specific bit-fields, which correlate to various sections of the tables in the transport stream.
	pointer_field = pid_in[4] & 0x00ff;

	short int index = (pointer_field + 5) & 0x00ff;

	table_id = pid_in[index] & 0x00ff;
	
	index++;
	section_syntax_indicator = (pid_in[index] & 0x0080) >> 7;

	zero = (pid_in[index] & 0x0040) >> 6;

	reserved1 = (pid_in[index] & 0x0030) >> 4;
	
	index++;
	section_length = ((pid_in[index - 1] & 0x000f) << 8) + (pid_in[index] & 0x00ff);
	
	index++;
	ts_id = pid_in[index] + pid_in[index + 1];
	
	index++;
	reserved2 = (pid_in[index] & 0x00C0) >> 6;

	version_number = (pid_in[index] & 0x003E) >> 1;

	current_next_indicator = pid_in[index] & 0x0001;

	index++;
	section_number = pid_in[index] & 0x00ff;

	index++;
	last_section_number = pid_in[index] & 0x00ff;

	for_loop_number = ((section_length * 8) - 72) / 32;
	
	CRC_32 = ((pid_in[section_length + pointer_field + 4] & 0x00ff) << 24) + ((pid_in[section_length + pointer_field + 5] & 0x00ff) << 16) + ((pid_in[section_length + pointer_field + 6] & 0x00ff) << 8) + (pid_in[section_length + pointer_field + 7] & 0x00ff);

	if (pat_cnt <= pat_max) {

		if (pat_cnt > 1) {
			printf("\n\t\t\t\t\t\t\tPress ""enter"" to print the next PAT\n");
			getchar();
		}

		if (adaptation_field_control == 1) {

			printf("\nAn example of the Program Association Table (PAT) has been found in packet number %d.\n", pid_cnt);
			printf("\nPAT No. %g:\n", pat_cnt);
			printf("\n-----------------------------------------------");
			printf("\nPointer Field           | %d", pointer_field);
			printf("\n-----------------------------------------------");
			printf("\nTable ID                | %x", table_id);
			printf("\n-----------------------------------------------");
			printf("\nSection Syntax Indicator| %x", section_syntax_indicator);
			printf("\n-----------------------------------------------");
			printf("\n          '0'           | %d ", zero);
			printf("\n-----------------------------------------------");
			printf("\nReserved Field          | %d ", reserved1);
			printf("\n-----------------------------------------------");
			if (section_length >= 13) {
				printf("\nSection Length          | %d bytes", section_length);
			}
			else printf("\nSection Length          | %d bytes               <- this is an erroneous reading (must be at least 13). Please check your TS format.", section_length);
			printf("\n-----------------------------------------------");
			printf("\nTransport Stream ID     | %d", ts_id);
			printf("\n-----------------------------------------------");
			printf("\nReserved Field          | %d ", reserved2);
			printf("\n-----------------------------------------------");
			printf("\nVersion Number          | %d", version_number);
			printf("\n-----------------------------------------------");
			printf("\nCurrent Next Indicator  | %d ", current_next_indicator);
			printf("\n-----------------------------------------------");
			printf("\nSection Number          | %d", section_number);
			printf("\n-----------------------------------------------");
			printf("\nLast Section Number     | %d", last_section_number);
			printf("\n-----------------------------------------------");
			printf("\nNo. of Loops in For-Loop| %d", for_loop_number);              //issue here (need to be able to print decimal) and with getting stuck in the below For loop

			int pn_cnt = 1;

			int loop_size = 4;

			for (int j = 13; j <= section_length; j += loop_size) {

				pn_cnt++;

				if (j == 1) {
					printf("\n\t\t\t\tFOR-LOOP CONTENTS:");
				}

				program_number = (pid_in[j + pointer_field] << 8) + pid_in[j + 1 + pointer_field];

				printf("\n\t\t\t\t%d) Program Number %d", (j - 13) / 4 + 1, program_number);

				reserved3 = pid_in[2 + j + pointer_field] & 0x00E0;

				printf("\n\t\t\t\tValue of reserved field is %d", reserved3);

				if (program_number == 0) {
					network_pid = ((pid_in[2 + j + pointer_field] & 0x001f) << 8) + (pid_in[3 + j + pointer_field] & 0x00ff);
					printf("\n\t\t\t\tNetwork PID of %d found here\n", network_pid);
				}

				else {
					pmt_pid = ((pid_in[2 + j + pointer_field] & 0x001f) << 8) + (pid_in[3 + j + pointer_field] & 0x00ff);
					printf("\n\t\t\t\tPMT PID of %d found here\n", pmt_pid);
				}

			}
			printf("\n-----------------------------------------------");
			printf("\nCRC_32 Value            | 0x%x", CRC_32);
			printf("\n-----------------------------------------------\n\n");


			printf("\n\n\n\nAdaptation field value = %d", adaptation_field_control);
		}

		else if (adaptation_field_control == 2) {
			printf("\n\nThis packet contains a an adaptation field.\n\n");
		}

		else if (adaptation_field_control == 3) {
			printf("\n\nThis packet contains a an adaptation field followed by a PAT.\n\n");     //find a way to re-calculate and print the PAT in this instance
		}

		else if (adaptation_field_control == 0) {
			printf("\n\nThis packet contains a reserved adaptation field.\n\n");
		}
	}

}



void headerCheck(void) {

	sync_byte = pid_in[0];

	if (sync_byte != 0x47) {
		printf("\n\nERROR STATEMENT:\nUnable to properly sync to stream format. Please check the format and packet length of your TS capture.\n");
		getchar();
	}

	transport_error_indicator = (pid_in[1] & 0x0080) >> 7;
	if (transport_error_indicator == 1) {
		printf("\nTransport Error indicated here\n");
		transport_error_cnt++;
	}

	payload_unit_start_indicator = (pid_in[1] & 0x0040) >> 6;

	transport_priority = (pid_in[1] & 0x0020) >> 5;
	if (transport_priority == 1) {
		priority_cnt++;
	}

	transport_scrambling_control = (pid_in[3] & 0x00C0) >> 6;
	if (transport_scrambling_control != 0 && pid_number == 0x0000) {
		printf("\n!!This PAT is scrambled!!\n");
	}

	adaptation_field_control = (pid_in[3] & 0x0030) >> 4;

	continuity_counter = pid_in[3] & 0x0f;                             //Need to be able to count through this from 0-15 and print errors
}



void continuityCounter(void) {

	/*This is only doing a CC check for the PAT PID (0x0000) and will need to be implemented separately for other PIDs*/


	if (pat_cnt == 1) {
		cc_cnt = continuity_counter;
	}
	else if (pat_cnt > 1) {
		cc_cnt++;
	}

	if (cc_cnt > 15) {
		cc_cnt = 0;
	}

	if (cc_cnt != continuity_counter) {
		printf("\n\nERROR MESSAGE:\nThere is an error in PAT packet continuity here!\n\n");
		cc_error++;
	}

}



/*This void function serves to print out all of the final figures, like the total number of PIDs, unique PIDs,
audio and video PIDs etc. and work out/print any relevant percentages.*/
void FINALstats(void) {
	pat_perc = 100 * pat_cnt / pid_cnt;
	pmt_perc = 100 * pmt_cnt / pid_cnt;
	error_perc = 100 * transport_error_cnt / pid_cnt;


	printf("\n\n\n\n\n -------------\n");
	printf("| FINAL STATS |");
	printf("\n -------------");
	printf("\n\n\nTOTAL NUMBER OF PACKETS: %d\n\n", pid_cnt);
	printf("\n\n\nTOTAL NUMBER OF TRANSPORT ERRORS: %d\n", transport_error_cnt);
	printf("\n\t\tTransport Error percentage: %.3f%% \n\n", error_perc);
	printf("\nTOTAL NUMBER OF PATS: %g\n", pat_cnt);
	printf("\n\t\tPAT to Total Packet percentage: %.3f%% \n", pat_perc);
	printf("\n\n\nTHERE WERE %d HIGH PRIORITY PACKETS\n", priority_cnt);
	printf("\n\n\nTHERE WERE %d PAT CC ERRORS\n", cc_error);

	printf("\n\n\n\n\n\n\n\n\n\n\n");
}



//To reset my global variables for a repeat of the program
void reset(void) {
	pid_cnt = 0;
	pat_cnt = 0;
	pmt_cnt = 0;
	unique = 0;
	unique_cnt = 0;
	transport_error_cnt = 0;
	priority_cnt = 0;
	cc_cnt = 0;
	cc_error = 0;
}




/*This is the main function, controlling the order in which everything is called and runs, and returning 0 at the end,
to finish the program. It contains the title and intro, lots of working out different PIDs etc. using bitwise operators,
 and calls the different funtions (seen above) under the appropriate conditions.*/
int main(int argc, char *argv[]) {

	printf("\n GEORGE KROON'S MPEG-2 PAT Printer  -  19/02/2019 \n");
	printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
	printf("\n\nThe purpose of this program is to print details of the \nProgram Association Tables in an MPEG 2 Transport Stream. \n(For TS of 188 Byte Packet Length, but this is re-configurable)\n\n");

	char *path;
	do {

		//Creating an empty character string called "path" and then printing to it it like the printf function does to the screen.

		if (argc > 1) {
			sprintf(&path, argv[1]);
			printf("%s", &path);
		}
		else {
			printf("\n\nMake sure your TS capture is saved to path ""Z:\\ZtempGK\\"" and press any key to proceed.\n\n");
			getch();
			printf("Please enter the name and file extension of your TS capture [e.g. ""File.ts""]:");
			scanf("%s", &file_name);
			sprintf(&path, "Z:\\ZtempGK\\%s", file_name);
		}


		//Opening the transport stream file.
		ts_file = fopen(&path, "rb");

		if (ts_file != NULL) {

			//Finding file size here
			fseek(ts_file, 0L, SEEK_END);
			file_length = ftell(ts_file);
			flength_MB = file_length / (1000 * 1024);
			printf("\n\nFile of size %.3f MegaBytes has been found\n", flength_MB);
			rewind(ts_file);

			printf("\n\nHow many PATs would you like to extract from the TS?\n\n");
			scanf("%d", &pat_max);

			getchar();
			printf("\n\nPress enter to begin\n\n");
			getchar();

			//Parse through the file.
			do {
				bytes_read = fread(pid_in, sizeof(char), PID_LENGTH, ts_file);
				pid_cnt++;

				//Bitwise for the actual PIDs of the packets.
				char upper = pid_in[1];
				char lower = pid_in[2];
				pid_number = upper & 0x001f;
				pid_number = (pid_number << 8) + lower;


				headerCheck();


				//"If" statements, counting the PATs or PMTs when they are found, and calling the relevant functions if their PID comes up.
				if (pid_number == 0x0000) {
					pat_cnt++;
					PATsection();
					continuityCounter();
				}


			} while (bytes_read == PID_LENGTH);

			//Calling the "FINALstats" function to print a culmination of the analysis as a final list of figures.
			FINALstats();

			fclose(ts_file); /*Closing the transport stream file, so we are no longer reading data from it.*/
		}

		else {
			printf("\n\n\nFile not opened correctly.\n\n\n");
		}
		/*The negative result of my "if" statement error check for opening the file.*/

		reset();
		continue_program = 'y';

		printf("\nWould you like to have another go at this program?  [y/n]\n");
		scanf("%c", &continue_program);


		if (continue_program != 'y' && continue_program != 'n') {
			printf("\nPlease enter ""y"" to continue, or ""n"" to exit.\n\n");
			scanf("%c", &continue_program);
		}



	} while (continue_program != 'n' && continue_program == 'y');



	getchar();
	/*This function allows the results to print to the screen. */

	printf("\n\n\nClosing the program");

	_sleep(170);
	printf(".");
	_sleep(170);
	printf(".");
	_sleep(170);
	printf(".");
	_sleep(170);
	printf(".");
	_sleep(170);
}
