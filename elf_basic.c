/* By Ryoon Ivo - ryoonivo@protonmail.com */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

void banner(void);
int suppcheck(Elf64_Ehdr *elfhdr, char *fdmmap);
int elfhdr_snarf(Elf64_Ehdr *elfhdr, char *fdmmap);
int elfphdr_snarf(Elf64_Phdr *elfphdr, char *fdmmap);
void cleanup(int fd);

void banner(void){
    puts("\nExamine a binaries ELF structures");
    puts("Usage: elfdump <filename> \n");
    exit(EXIT_FAILURE);
}

int suppcheck(Elf64_Ehdr* elfhdr, char* fdmmap){
    elfhdr = (Elf64_Ehdr *)fdmmap;
    
    if(elfhdr->e_ident[ELFDATA2LSB]){
        puts("\nSystem is little endian");
    }
    else{
        puts("\nSystem is not little endian!");
        return(-1);
    }
    
    if((elfhdr->e_ident[EI_MAG0] != ELFMAG0) || (elfhdr->e_ident[EI_MAG1] != ELFMAG1) || (elfhdr->e_ident[EI_MAG2] != ELFMAG2) || (elfhdr->e_ident[EI_MAG3] != ELFMAG3)){
        puts("\nSorry, the file int not a valid ELF!");
        return(-1);
    }
    
    if(!elfhdr->e_ident[ELFCLASS64]){
        puts("\nSorry, the file is not for a 64 bit architecture! \n");
        return(-1);
    }
    
    if(elfhdr->e_machine != EM_X86_64){
        puts("\nSorry, the file is not a supported ADM x86-64 type! \n");
        return(-1);
    }
    
    if(elfhdr->e_version == EV_NONE){
        puts("\nSorry, the file is not a supported ELF version! \n");
        return(-1);
    }
    
    return 0;
}

int elfhdr_snarf(Elf64_Ehdr* elfhdr, char* fdmmap){
    elfhdr = (Elf64_Ehdr *)fdmmap;
    puts("\n+++ ~~ ELF Header Entries ~~ +++");
    fprintf(stderr, "ELF machine type            -> [%d]\n", elfhdr->e_machine);
    fprintf(stderr, "ELF object file type        -> [%d]\n", elfhdr->e_type);
    fprintf(stderr, "ELF object file version     -> [%d]\n", elfhdr->e_version);
    fprintf(stderr, "ELF header size             -> [%d]\n", elfhdr->e_ehsize);
    fprintf(stderr, "ELF entry position          -> [%d]\n", elfhdr->e_entry);
    fprintf(stderr, "ELF program header count    -> [%d]\n", elfhdr->e_phnum);
    fprintf(stderr, "ELF program offset          -> [%d]\n", elfhdr->e_phoff);
    fprintf(stderr, "ELF program entry size      -> [%d]\n", elfhdr->e_phentsize);
    fprintf(stderr, "ELF section header count    -> [%d]\n", elfhdr->e_shnum);
    fprintf(stderr, "ELF section offset          -> [%p]\n", elfhdr->e_shoff);
    fprintf(stderr, "ELF section entry size      -> [%d]\n", elfhdr->e_shentsize);
    return 0;
}

int elfphdr_snarf(Elf64_Phdr* elfphdr, char* fdmmap){
    elfphdr = (Elf64_Phdr *)fdmmap;
    puts("\n+++ ~~ Program Header Entries ~~ +++");
    fprintf(stderr, "Program virtual address     -> [0x%.8x]\n", elfphdr->p_vaddr);
    fprintf(stderr, "Program physical address    -> [0x%.8x]\n", elfphdr->p_paddr);
    fprintf(stderr, "Program offset              -> [%p]\n", elfphdr->p_offset);
    fprintf(stderr, "Program align               -> [%d]\n", elfphdr->p_align);
    fprintf(stderr, "Program filesize            -> [%d]\n", elfphdr->p_filesz);
    fprintf(stderr, "Program memory size         -> [%d]\n", elfphdr->p_memsz);
    return 0;
}

void cleanup(int fd){
    close(fd);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv){
    int fd, opts;
    char *fdmmap = NULL;
    char *filename = NULL;
    off_t size;
    
    extern char *optarg;
    extern int optind;
    
    Elf64_Ehdr *elfhdr;
    Elf64_Phdr *elfphdr;
    
    if(argc < 2){
        banner();
    }
    
    while(optind < argc){
        filename = (char *)malloc(strlen(argv[optind] + 1));
        memcpy(filename, argv[optind++], 15);
    }
    
    fd = open(filename, O_RDONLY);
    if(fd < 0){
        perror("open");
        exit(EXIT_FAILURE);
    }
    
    size = lseek(fd, 0, SEEK_END);
    if(size < 0){
        perror("lseek");
        cleanup(fd);
    }
    
    fdmmap = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(!fdmmap){
        perror("mmap");
        cleanup(fd);
    }
    
    if(suppcheck(elfhdr, fdmmap) != 0){
        cleanup(fd);
    }
    
    if(elfhdr_snarf(elfhdr, fdmmap) < 0){
        puts("Failed to snarf\n");
    }
    
    if(elfphdr_snarf(elfphdr, fdmmap) < 0){
        puts("Failed to snarf\n");
    }
    
    free(filename);
    close(fd);
    
    return(EXIT_SUCCESS);
}
