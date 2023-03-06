<h1 align="center">Ring Relay</h1>


## Status
```diff
+ Front-end required for the features mentioned below completed
@@ Implementing Back-end @@ [This Repo]
```

##### Note: this isn't the repo for the app mentioned on my linkedin or resume, this is a complete remake version of the Ring Relay I've built a year ago

## About

A chatting app that lets you see different stats about your texts and conversations such as freqency maps for words, average length of each message and more. I'd love for this app to use a dynamic unique design. I'll also implement end-to-end encryption using a public-private key pair for each user. I'll detail the architecture implemented later on.

## Tech Stack

### Backend

Even if the most efficient back-end solution for this type of real-time app is to use websockets, Heroku removed their free tier so as a result I'm gonna use Vercel Serverless functions as the basis for the backend. I'll use the Firebase Realtime DB as a conversation buffer to enable near-instant delivery of the messages between users while the backend also sends the message objects to Planet Scale for permanent storage. 

### Frontend

I feel like I'm already profficient with Vue because I used it for more than a year now so I'd really like to have the same level of familiarity with React cuz I enjoy using it just as much and it's also really popular.

### Databases

Since I already have 3 years of experience working with Mongo DB, I'll try out PlanetScale just for some novelty (this isn't a techinal driven decision cuz I'll be using this app with friends only anyway)(also I'd like to get some experience with SQL based DBs). I'll stick to Firebase Realtime DB for storing sessions and any other temporary data such as reset password tokens.

## Development Method

I'll use a Github project to track everything that needs doing and the progress on every task. Since I'm a big fan of Agile, I'll do the bulk development in sprits spanning a couple of days and use the same method for adding new features later on.

## Architecture In-Depth

### DB Schema
<p align="center">
  <img src="/docs/Ring Relay Architecture(DB Schema).png"></img>
</p>

The Planet Scale hosted Mysql DB contains 2 main tables (users and refs) that contain all user account data and the relations between how users are connected to eachother. Each user then has its own table that has the name UM`${UID}`. The purpose of this table is to contain all messages sent or received for that specific user, depending on who started the connection. For example, the picture below contains the flowchart of how this new contact process would take place.

### New Contact Flow
<p align="center">
  <img src="/docs/Ring Relay Architecture (New Contact Flow).png"></img>
</p>

The flowchart above ilustrates how an user (Client 0 / [C0]) will connect with another user (Client 1 / [C1]). At the end of this process, both users will have the other one saved in the `refs` table. I know using some sort of relation between this data would've been more efficient, but by allowing all users to have an independant array of contacts ensures access to those conversations even if one of the parties would delete the other one from their contacts on their end. 

### Message Retrival
<p align="center">
  <img src="/docs/Ring Relay Architecture (Retrieve Messages).png"></img>
</p>

Every time an users taps on a conversation, the flowchart above gets triggered so the front-end could display the conversation using the message array retrieved from the DB. The first step is retrieving the UIDs any given user is connected to, so the front-end could hydrate the 'chats' section of the UI. After the user selects a conversation, a request is sent containing the UID of the person the conversation is with. Then, the serverless function checks both the `UM${OWN[UID]}` table and if the conversation is not found there, the `UM${FOREIGN[UID]}` table. This is efficient since the conversation can be in one of the 2 places. (I considered adding a new field in the refs table to deal with this, but concluded it would add complexity that's not warranted when considering the trade-offs of both methods) 

### Message Exchange
<p align="center">
  <img src="/docs/Ring Relay Architecture (Message Exchange).png"></img>
</p>

Since the latency between users would be too high if I would've used serverless functions alone, I've decided to use the Firebase Realtime DB as a conversation buffer to deliver the messages near-instantly. This works by each active user(has a specific chat window open) having an unique JSON object stored in the RTDB at path `UID`. Any incoming messages from other users would be saved there while the session is active, and since the user client would be listening to changes at that specific path, as soon as a new message hits the buffer, it would then get relayed to the front-end. At the same time, the serverless function also adds a new row in the `UM${OWN}` or `UM${FOREIGN}` table to permanently store the messages.

#### I'm planning on adding more features like push notifications, MFA, and possibily audio and video calls, but first I'll be focusing on the basic features above.

