/*
 * Filter to read in a binary file and produce an xxd-style hex dump,
 * but with the sequence of bytes on the command line replaced with 
 * non-hex strings (e.g. WW XX YY ZZ)
 * 
 * Call with the sequence as hex bytes:-
 *   xxsubst 0F 1E 2D 3c ...
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int substitution_byte_count;
static int *substitutions;
static int *input_buffer;

static void print_next_byte(int byte)
{
	static size_t address = 0;
	
	if(!(address & 0x01))
	{
		if(!(address & 0x0F))
		{
			if(address)
			{
				fprintf(stdout, "\n");
			}
			
			fprintf(stdout, "%06x:", address);
		}
		
		fprintf(stdout, " ");
	}
	
	if(byte >255)
	{
		fprintf(stdout, "%c%c", 'A' + byte - 256, 'A' + byte - 256);
	}
	else
	{
		fprintf(stdout, "%02x", byte);
	}
	
	address++;
}

int main(int arg_count, char *args[])
{
	int i, starting_code;


	substitution_byte_count = arg_count - 1;
	if(substitution_byte_count < 4)
	{
		starting_code = 256 + 23;
	}
	else
	{
		starting_code = 256 + 26 - substitution_byte_count;
	}

/* allocate working buffers */
	if(substitution_byte_count > 0)
	{
		substitutions = (int *) 
				calloc(substitution_byte_count, sizeof(int));
		input_buffer = (int *) 
				calloc(substitution_byte_count, sizeof(int));
				
		if(!substitutions || !input_buffer)
		{
			perror("failed to allocate working buffers");
			return(1);
		}		
	}

/* read substitution string from the command line arguments */
	for(i = 0; i < substitution_byte_count; i++)
	{
		if(sscanf(args[i+1], "%x", substitutions + i) < 1)
		{
			fprintf(stderr, "Error in arguments: \"%s\" is not a hex byte\n",
					args[i + 1]);
			return(2);
		}
	}

/* pass input to output */
	for(i = 0; !feof(stdin) && !ferror(stdin); )
	{
		input_buffer[i] = fgetc(stdin);
		
		if(i < (substitution_byte_count - 1))
		{
			i++;
		}
		else
		{
			int j;
			
			for(j = 0; j < substitution_byte_count 
							&& substitutions[j] == input_buffer[j]; j++)
				;
			
			if(j == substitution_byte_count)
			{
				for(j = 0; j < substitution_byte_count; j++)
				{
					print_next_byte(starting_code + j);
				}
				
				i = 0;
			}
			else
			{
				print_next_byte(input_buffer[0]);
				memmove(&(input_buffer[0]), &(input_buffer[1]),
						(substitution_byte_count - 1)*sizeof(int));
			}
		}
	}
	
/* flush the buffer and exit */
	while(i < 0)
	{
		print_next_byte(input_buffer[0]);
		memmove(&(input_buffer[0]), &(input_buffer[1]),
						(substitution_byte_count - 1)*sizeof(int));
		i--;
	}
	
	fprintf(stdout, "\n");
	
	free(substitutions);
	free(input_buffer);
	
	return(0);
}
