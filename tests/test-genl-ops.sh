#!/bin/bash

pgm=../src/route-cli
echo ==show==
$pgm show
echo ==add==
$pgm add 2.2.2.2/8
$pgm add 2.2.2.2/16
$pgm add 2.2.2.2/24
$pgm show
echo ==find==
$pgm find 2.2.2.2
echo ==delete==
$pgm delete 2.2.2.2/16
$pgm show
echo ==find==
$pgm find 2.2.2.2
echo ==delete match==
$pgm delete 2.2.2.2
$pgm show
echo ==find==
$pgm find 2.2.2.2
echo ==add==
$pgm add 2.2.2.2/8
$pgm add 2.2.2.2/16
$pgm add 2.2.2.2/24
$pgm show
echo ==clear==
$pgm clear
$pgm show
