# Open group policy managment tool

Under Group Policy Objects
1. create a new policy
2. Enter a name
3. Expland end Edit
4. Go to Computer Configuration > Administrative Templates > Windows Components > OneDrive
5. Enable the option named Prevent the usage of OneDrive for file storage
6. Apply and save

Now you want have to link it
1. On the Group policy management screen, you need to right-click the Organizational Unit desired and select the option to link an existent GPO
2. Link your new group policy to the root of the domain
3. Open cmd and type `gpupdate`