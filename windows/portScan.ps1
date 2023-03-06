param($target)
if(!$target){
    echo "Por favor digite um alvo válido"
    echo "exemplo \.script.ps1 google.com"
} else { 
    foreach($port in 50..80){
        $replyt = Test-netconnection $target -P $port -WarningAction SilentlyContinue -InformationLevel Quiet
       #echo $replyt
        if($replyt -eq "True"){
            echo "${target}:${port} -- OPEN" 
        } else {
            #Porta fechada
            }
    }
    #Test-netconnection $target -P 80 -WarningAction SilentlyContinue -InformationLevel Quiet
}