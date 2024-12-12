from django.shortcuts import render
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserRegistrationSerializer, NoteSerializer
from .models import Note, CustomUser
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

class Register(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.set_password(serializer.validated_data['password'])
            user.save() 
            return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class Login(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        identifier = request.data.get('identifier')
        password = request.data.get('password')
        if len(password) < 8:
            return Response({"error": "Password must be at least 8 characters long."}, status=status.HTTP_400_BAD_REQUEST)
        if len(identifier) < 6 and '@' not in identifier:
            return Response({"error": "Username must be at least 6 characters long."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            if '@' in identifier:
                user = CustomUser.objects.get(email=identifier)
            else:
                user = CustomUser.objects.get(username=identifier)
            if check_password(password, user.password):
                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                })
            else:
                return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            return Response({"error": "User does not exist"}, status=status.HTTP_400_BAD_REQUEST)

class GetToken(APIView):
    def post(self, request):
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response({"error": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            new_access_token = token.access_token
            return Response({
                'access': str(new_access_token),
                'refresh': str(token)
            })

        except TokenError:
            return Response({"error": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST)

class Logout(APIView):
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')

            if refresh_token is None:
                return Response({"error": "No refresh token provided."}, status=status.HTTP_400_BAD_REQUEST)

            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Successfully logged out."}, status=status.HTTP_200_OK)

        except TokenError:
            return Response({"error": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST)

class NoteCreate(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = NoteSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class NoteRead(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        notes = Note.objects.filter(user=request.user)
        serializer = NoteSerializer(notes, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class NoteUpdate(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, noteid):
        try:
            note = Note.objects.get(noteid=noteid, user=request.user)
            data = {}
            if 'title' in request.data:
                data['title'] = request.data['title'].strip()
            if 'text' in request.data:
                data['text'] = request.data['text'].strip()

            if not data:
                return Response({"error": "No valid fields to update"}, status=status.HTTP_400_BAD_REQUEST)

            for field in data:
                current_value = getattr(note, field)
                new_value = data[field]
                if current_value == new_value:
                    return Response({"error": f"The {field} is already set to this value."}, status=status.HTTP_400_BAD_REQUEST)

            serializer = NoteSerializer(note, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "message": "Note updated successfully.",
                    "note": serializer.data
                }, status=status.HTTP_200_OK)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Note.DoesNotExist:
            return Response({"error": "Note does not exist or does not belong to user"}, status=status.HTTP_404_NOT_FOUND)

class NoteDelete(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, noteid):
        try:
            note = Note.objects.get(noteid=noteid, user=request.user)
            note.delete()
            return Response({"message": "Note deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        except Note.DoesNotExist:
            return Response({"error": "Note does not exist or does not belong to user"}, status=status.HTTP_404_NOT_FOUND)

class DeleteAllData(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user
        try:
            notes = Note.objects.filter(user=user)
            notes.delete()
            return Response({"message": "All data deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)