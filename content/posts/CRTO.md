---
layout: single
date: 2022-04-22
title: "Certified Red Team Operator (CRTO) by Zero Point Security Review"
toc: true
draft: false
type: ["posts","post"]
categories:
  - Courses
tags:
  - ActiveDirectory
  - RedTeam
  - CobaltStrike
  - Certifications
---
## Introduction
[Red Team Ops](https://courses.zeropointsecurity.co.uk/courses/red-team-ops) is a course offered by Zero Point Security, serves as an Introduction to Red Teaming with a focus on the use of Cobalt Strike C2. When the students finish the course and pass the 48 hour exam (don't worry, it's not like the 300 level courses by OffSec), the students will receive the "Certified Red Team Operator" certification.
If you're new to the community, Zero Point Security is a one-man company created and operated by Daniel Duggan aka RastaMouse. He is well known in the infosec community for many his contributions such as the open-source [SharpC2](https://github.com/SharpC2/SharpC2), the ProLab [RastaLabs](https://app.hackthebox.com/prolabs/overview/rastalabs) on HackTheBox, the [C2 Development in C# Course](https://courses.zeropointsecurity.co.uk/courses/c2-development-in-csharp), the [Offensive Driver Development Course](https://courses.zeropointsecurity.co.uk/courses/offensive-driver-development) and the famous RTO course that I will we talking about.

In this post I will be going over my experience with the course and the exam, what I think about this course and whether you should be taking it or not (spoiler: yes, you should!).

## My Background
I am still a fresh noob when it comes to the Offensive Security domain, with less than a year of experience as a pentester while writing this. I did however have prior experience working as a SOC analyst, so I joined the Red side with a hint of Blue, and this has benefited me greatly (I'll get to that part later). I had my OSCP and CRTP in November 2021 and January 2022 respectively, my knowledge and skills could barely scratch the surface in the world of Pentesting/Red Teaming, but at least I consider myself knowing "how to computer".
I've always wanted to dive into Red Teaming and Adversary Emulation, so after CRTP, CRTO was next on my checklist.

## The Course Material and Lab Experience
The course content was absolutely amazing, it goes over from the basic "high level" of what is Red Teaming, what is a C2, Reconnaissance, Initial Compromise, to full Domain Takeover.

I enjoyed the "high level" theory part of Red Teaming more than I thought I did, so I went ahead and buy the book [Red Team Development and Operations](https://www.amazon.com/Red-Team-Development-Operations-practical/dp/B083XVG633) by Joe Vest and James Tubberville. This is an amazing book and probably a must-read if you want to get into Red Teaming.
There are 26 modules in the course so I won't be able to go over each of them here, but here are what I think to be the highlights of the course.

### Cobalt Strike
Of course, what's not to love about getting your hands on one of the best C2 framework out there. Cobalt Strike was originally created by Raphael Mudge back in 2012, it is now  maintained by Help System and still is one of the best C2 frameworks out there due to its powerful and robust capabilities. I've never got a chance to use Cobalt Strike or any of the C2 framework before, and to be honest, this was an eye-opening experience. Since the course focuses on the use of C2, everything you do will be via Cobalt Strike, from catching the first beacon from a macro-embedded Word doc, host privsec, lateral movement, pivoting, tunneling, to getting DA and EA.
{{< image src="/images/cs.png" alt="Cobalt Strike in action" position="center" style="border-radius: 8px;" >}}

The course also touched on some basic AV for Cobalt Strike payloads, by modifying the artifact-kit and resource-kit to bypass AV on the target machines (not EDR evasion unfortunately, RastaMouse did hint that this topic would be covered in RTO2, so I guess we'll see). Another cool feature of Cobalt Strike is Malleable C2 Profile, it gives the Operators total control of the beacon's indicators such as network and in-memory artifacts, HTTP(S) requests coming in and out, everything is fully customisable. This features can make Cobalt Strike much harder to detect, and can also be used to emulate the TTPs of a particular APT in an Red Team Engagement.

### Kibana
Ah, flashback to the SOC days. In previous verisons of the lab, Splunk was the tool of choice, however the new lab uses ELK as a mini 'SIEM'. In my opinion, this is a great feature and a selling point for RTO. Yes, attacking a network is cool but what's cooler is you get to see what's going on on the other side of the fence, you get to see what the Blue Team Operators see. Combining with the #OPSEC tips and tricks, I got to see what event Windows generates via Kibana when you launch an attack, why is this particular technique is considered bad #OPSEC and what should you do instead to be more stealth.
I had many "Ahhhhhh" moments as I was going through the course and looking at the Kibana console, I'd be lying if I say I know 100% some events mean and why they were there when I was a SOC analyst. But now from an attacker perspective, it all made sense. This is why I strongly believe that to be a good Red Team Operator, you also need to be a good Blue Team Analyst and vice versa. It's Art of War all over again, "Knowing Your Enemy".
{{< image src="/images/kibana.png" alt="Kibana" position="center" style="border-radius: 8px;" >}}

A small issue I encountered was, sometimes, the winlogbeat sensor did not work properly on some machines and I ended up not seeing any events showing on the Kibana console.

### Active Directory Exploitation
This was the bulk of the course, teaching you how to exploit a Windows Active Directory environment. I felt like CRTP was a great primer for me for basic understanding of AD exploitation, this time, I was doing it all over again with Cobalt Strike. But that does not mean that I did not learn anything new. The AD Exploitation modules on RTO really reinforced my skills and taught me new techniques on Lateral Movement, Reverse Port Forwarding, Pivoting, DPAPI, GPO Abuses, DCAL Abuses, LAPS and Active Directory Certificate Services (ADCS).

The section on ADCS was absolute gold, thanks to it, I was able to get DA in a recent internal pentest by abusing NTLM Relay via ADCS (PetitPotam attack). I will make a detailed post on this in a few weeks.

### The Lab
The lab for RTO was hosted on SnapLab, overall, it was a smooth experience for me. Everything was done via a web portal using Guacamole Apache, you connect to the lab directly through it. All tools were provided on the attacker-machine, it was a complete sandboxed environment to protect Cobalt Strike's license (understandable). There was no flag to collect in the unlike the previous versions of the lab. It was designed so that you can follow a long the examples in the course material and experiment with different techniques and tactics, more like an "Open World" lab ;)

Also, the lab is private and you would not have to share it with others. Phew!

### Pricing and Support
RTO was relatively cheap when you compare it to other big players in the game like Offensive Security, SANS and INE. I bought RTO the bundle of the course + 40 hours of lab time for £399 (if you buy the lab time separately, it is £1.25 per hour). I finished the course and the exam and had about 10 hours of lab time remaning, which I still have access to anytime. With everything the course provided, it was an absolute bargain, not to mention, you have lifetime access to the course material and its future updates.

For support, since RastaMouse in the CEO, Content Manager, Lab Maintainer as well as Student Support Officer, he might be overwhelmed with emails and queries. RTO's [Discord](https://discord.com/invite/FBgTXB45?utm_source=Discord%20Widget&utm_medium=Connect) server is the place to go for real time support. You will have RastaMouse himself answering your questions, when he is unable too, you have heaps of other knowledgable members in the chat to help you out. It is also a good place for banters :)

## Exam
The exam was a roller coaster for me. I booked to sit the exam on Good Friday, so that I could make good use of the Easter long weekend. After booking the exam, you would receive a PDF containing the TTPs you need to emulate using Malleable C2 Profile and custom tactical approach. The exam is a 4-day event for 48 hours (you have 48 hours to do the exam,  the result will come out after 4 days), and the best thing is you can pause the exam anytime you want for breaks, 48 hours is a lot of time so make sure you eat and sleep well to keep your mind fresh. To pass you would need to collect 6/8 flags, no report required, which was a nice change of wind.

My first day did not go so well, I got 2 flags in the first 4 hours, and got stuck for the next 7 hours. I thought I've tried everything, I didn't know what I was missing. Frustrated, I went to bed, I spent the whole Saturday out playing Squash, had dinner with friends and played Mario Kart :'). I think I just needed a break. Picked up where I left off on Sunday, I finally got my third flag, then fourth. "They're falling like Dominoes now" I told myself, it was all fun and games until flag 6, the passing flag. I went full r*tard and reset the firewall setting on one box, what could go wrong right? It effectively killed a very important beacon in the compromise chain, and I completely lost connection to that machine. I was pulling my hair out. 

Oh well, I had 26 hours left, so I reverted everything and started from square one. Took me a while to get to the point I was before, and yes, I finally got flag 6 at 2am. Had a bit too much coffee by then so I tried grinding out the next 2 flags, and managed to get 8/8 at 4.30am after 20 hours straight (I should stop doing this to myself, I know).
{{< image src="/images/exam.png" alt="Exam Timeline" position="center" style="border-radius: 8px;" >}}
*My exam timeline*
{{< image src="/images/cert.png" alt="Exam Timeline" position="center" style="border-radius: 8px;" >}}


## Final Thoughts
For me, RTO was the best course I've ever taken so far, material was top notch, great lab experience, and I actually enjoyed doing the course. Can't wait for RTO2 :)
\
I will start OffShore ProLab on HackTheBox in a week or two, now I've got the knowledge, let's put it into the test and gain some more skills! After that, OSEP is next on my list.

Should you take this course? **Yes!!**
\
Are you a pentester who wants to step up your AD and internal network testing game? **Big Yes**
\
Are you wanting to transit to Red Teaming? **Ohhh Yesss!**
\
Are you a Blue Team Operator/SOC Analyst who wants to use the knowledge from the Offensive side to reinforce your Defending/Detection game? **Heck Yes!**
\
Are you not in Tech at all and having no clue how you got here? **Um, maybe not CRTO yet, but if you like the sound of it, start hacking :")**