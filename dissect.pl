#!/bin/perl

# Dissect

use strict;
use warnings;

use Capstone ':all';
use Data::Dumper;
use Term::ANSIColor qw(:constants);
## CLI ##

use Getopt::Long;
use Pod::Usage;

my %defines; 
my $binary;
my $address; # Find a better way of finding address
my $cs;

my $help = 0;
my $version = 0;

GetOptions ('help|?'   => \$help, 
            'version'  => \$version,
            'binary=s' => \$binary,
            'define=s' => \%defines,
            'address=s' => \$address,
            'x'  => \&disasm
        )
             or pod2usage(2);
pod2usage(1) if $help;
print "dissect 0.0.1\n" if $version;

# Add \x delimiter to binary hex

sub binary {
 
      # Read binary data
    my ($binary_file) = pop @_;
 
    print "[+] Loading file: $binary_file\n";
 
    # Read binary
    open my $in, '<', $binary_file or die;
    binmode $in;
    
    my $bin;
    my @shcode;

    read $in, $bin, -s $in;
    print "[+] Success\n";

    my @values = split('', $bin);

    my $shcode;
    
    print "[+] This may take a few seconds..\n";

    foreach my $val (@values) { 
        chomp($val);

        push(@shcode, '\x'.unpack("H8", "$val"));

        $shcode = join('', @shcode);
    }

    print "[+] Getting everything ready..\n";

    return($shcode);
}
 
 sub disasm {

    my $bin_shellcode = binary($binary);

    # Check defines
    print "[+] Checking defines..\n";

    my $size = keys %defines;
 
    die "Error: No defines found, stopped" if $size == 0;

    print "[+] Found defines: \n\t";
    print "Engine: $defines{engine}\n\tSyntax: $defines{syntax}\n";
    
    print "[+] Setting up for disassembly..\n";

    # Check which architecture was defined
    #
    # Capstone currently supports:
    #   CS_ARCH_ARM 
    #   CS_ARCH_MIPS
    #   CS_ARCH_PPC
    #   CS_ARCH_SPARC
    #   CS_ARCH_SYSZ
    #   CS_ARCH_X86
    #   CS_ARCH_XCORE

    if    ($defines{engine} =~ /[x86]/i) { $cs = Capstone->new(CS_ARCH_X86, CS_MODE_64); }
    elsif ($defines{engine} =~ /[arm]/i) { $cs = Capstone->new(CS_ARCH_X86, CS_MODE_64); }
    elsif ($defines{engine} = /[mips]/i) { $cs = Capstone->new(CS_ARCH_X86, CS_MODE_64); }
    elsif ($defines{engine} = /[sparc]/i) { $cs = Capstone->new(CS_ARCH_X86, CS_MODE_64); }
    else { print "[+} Please provide a supported arch\n" }

    # Default is set to Intel
    # $cs->set_option(CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL); 

    if ($defines{syntax} =~ /[att]/i) { $cs->set_option(CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT); }

    $cs->set_option(CS_OPT_DETAIL, CS_OPT_ON);

    my @insn = $cs->dis($bin_shellcode, $address, 0);
    local $Term::ANSIColor::AUTORESET = 1;
    foreach(@insn) {
        printf "  0x%.16x  %-30s   %s %s\n",
        $_->{address},
        hexlify($_->{bytes}),
        $_->{mnemonic},
        $_->{op_str};

        printf "     Read: %s\n", join(',', @{$_->{regs_read}});
        printf "     Write: %s\n", join(',', @{$_->{regs_write}});
        printf "     Groups: %s\n", join(',', @{$_->{groups}});
    }

    print "[+] " . scalar(@insn) . " instructions disassembled\n";
}

sub hexlify {

    my $bytes = shift;

    return join ' ', map { sprintf "%.2x", ord($_) } split //, $bytes;
}
