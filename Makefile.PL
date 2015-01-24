use ExtUtils::MakeMaker;

WriteMakefile(
    AUTHOR => 'Steven Haryanto <stevenharyanto@gmail.com>',
    NAME => 'Crypt::Password::Util',
    VERSION => 0.09,

    MIN_PERL_VERSION => "5.010001",
    PREREQ_PM => {
	"UUID::Random::Patch::UseMRS" => 0,
	"Test::More" => 0.98,
	"Sort::Version" => 0,
    },
);
