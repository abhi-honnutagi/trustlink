function changeScanner(){

let type=document.getElementById("scanType").value

document.getElementById("urlScanner").style.display="none"
document.getElementById("emailScanner").style.display="none"
document.getElementById("imageScanner").style.display="none"
document.getElementById("fileScanner").style.display="none"

if(type==="url")
document.getElementById("urlScanner").style.display="block"

if(type==="email")
document.getElementById("emailScanner").style.display="block"

if(type==="image")
document.getElementById("imageScanner").style.display="block"

if(type==="file")
document.getElementById("fileScanner").style.display="block"

}

// URL SCAN

async function scanURL(){

let url=document.getElementById("urlInput").value

let response=await fetch("http://127.0.0.1:5000/scan-url",{

method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({url:url})

})

let data=await response.json()

document.getElementById("urlResult").innerHTML =
"Result: "+data.result+
"<br>Trust Score: "+data.trust_score+
"<br>Domain Age: "+data.domain_age+
"<br>Server IP: "+data.ip_address+
"<br>IP Reputation: "+data.ip_reputation

loadHistory()

}

// EMAIL SCAN

async function scanEmail(){

let email=document.getElementById("emailInput").value

let response=await fetch("http://127.0.0.1:5000/scan-email",{

method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({email:email})

})

let data=await response.json()

document.getElementById("emailResult").innerHTML="Result: "+data.result

loadHistory()

}

// IMAGE SCAN
async function scanImage(){

let file=document.getElementById("imageUpload").files[0]

let formData=new FormData()

formData.append("image",file)

let response=await fetch("http://127.0.0.1:5000/scan-image",{

method:"POST",
body:formData

})

let data=await response.json()

document.getElementById("imageResult").innerHTML=
"Result: "+data.result+
"<br>Extracted Text:<br>"+data.detected_text

loadHistory()

}

// FILE MALWARE SCAN

async function scanFile(){

let file=document.getElementById("fileUpload").files[0]

let formData=new FormData()

formData.append("file",file)

let response=await fetch("http://127.0.0.1:5000/scan-file",{

method:"POST",
body:formData

})

let data=await response.json()

let output=""

output+="File: "+data.file_name+"<br>"
output+="Hash: "+data.file_hash+"<br>"
output+="Result: "+data.scan_result+"<br>"

if(data.malware_name){
output+="Malware Name: "+data.malware_name+"<br>"
output+="Severity: "+data.severity
}

document.getElementById("fileResult").innerHTML=output

loadHistory()

}

// DASHBOARD GRAPH

async function loadDashboard(){

let response = await fetch("http://127.0.0.1:5000/dashboard-stats")

let data = await response.json()

let ctx = document.getElementById("threatChart").getContext("2d")

let normalData=[
data.urls_scanned,
data.emails_scanned,
data.images_scanned,
data.files_scanned
]

let dangerMode=false

let chart = new Chart(ctx,{

type:"bar",

data:{
labels:["URLs","Emails","Images","Files"],

datasets:[{
label:"Security Data",

data:normalData,

backgroundColor:[
"green",
"green",
"green",
"green"
],

barPercentage:0.4,
categoryPercentage:0.5

}]
},

options:{
plugins:{
legend:{
onClick: async function(){

dangerMode=!dangerMode

if(dangerMode){

let res = await fetch("http://127.0.0.1:5000/scan-history")
let history = await res.json()

let urlThreat=0
let emailThreat=0
let imageThreat=0
let fileThreat=0

history.forEach(item=>{

if(item.result==="danger" || item.result==="suspicious"){

if(item.type==="URL") urlThreat++
if(item.type==="EMAIL") emailThreat++
if(item.type==="IMAGE") imageThreat++
if(item.type==="FILE") fileThreat++

}

})

chart.data.datasets[0].data=[
urlThreat,
emailThreat,
imageThreat,
fileThreat
]

chart.data.datasets[0].backgroundColor=[
"red",
"red",
"red",
"red"
]

}else{

chart.data.datasets[0].data=normalData

chart.data.datasets[0].backgroundColor=[
"green",
"green",
"green",
"green"
]

}

chart.update()

}
}
}
}

})

}

// HISTORY

async function loadHistory(){

let response=await fetch("http://127.0.0.1:5000/scan-history")

let data=await response.json()

let table=document.getElementById("historyTable")

table.innerHTML=""

data.forEach(item=>{

let row=`
<tr>
<td>${item.type}</td>
<td>${item.item}</td>
<td>${item.result}</td>
<td>${item.date}</td>
</tr>
`

table.innerHTML+=row

})

}


window.onload=function(){

loadDashboard()
loadHistory()

}