#!/usr/bin/env python
# Title           :cvss_calc.py
# Description     :Script to convert CVSS data from Nessus output
# Author          :Victor Mielke
# Date            :25/10/2020
# Version         :1.0
# Usage           :python cvss_calc.py
# Python_version  :3.8.2  


import pandas as pd
import numpy as np
import openpyxl as xl
import os
import win32com.client
import sys
import time
import msvcrt
import tkinter as tk
from tkinter import filedialog

  

print('##################################################################################')
print('#                               ______     ______ ____                           #')
print('#                              / ___\ \   / / ___/ ___|                          #')
print('#                             | |    \ \ / /\___ \___ \                          #')
print('#                             | |___  \ V /  ___) |__) |                         #')
print('#                              \____|  \_/  |____/____/                          #')
print('#                                                                                #')
print('#            ____    _    _     ____ _   _ _        _  _____ ___  ____           #')
print('#           / ___|  / \  | |   / ___| | | | |      / \|_   _/ _ \|  _ \          #')
print('#          | |     / _ \ | |  | |   | | | | |     / _ \ | || | | | |_) |         #')
print('#          | |___ / ___ \| |__| |___| |_| | |___ / ___ \| || |_| |  _ <          #')
print('#           \____/_/   \_\_____\____|\___/|_____/_/   \_\_| \___/|_| \_\         #')
print('#                                                                                #')
print('##################################################################################')


root = tk.Tk()
root.withdraw()

excel1 =  filedialog.askopenfilename()
dir_path = os.path.dirname(os.path.realpath(__file__))
df = pd.read_excel(excel1)

# Get CVSS V2 quando o V3 for null e faz o insert
df['CVSS Results'] = df['CVSS V3 Vector'].fillna(df['CVSS V2 Vector'])
df['CVSS Agrupado'] = df['CVSS Results']  # Copia CVSS Result
# Insere uma coluna index 0 como o valor da results
df.insert(loc=0, column='CVSS Results_2', value=df['CVSS Results'])
# Usa a coluna temporaria para gerar só os valores do V2 quando V3 for null
df['CVSS Results'] = df[df['CVSS Results_2'] != df['CVSS V3 Vector']]

new_df1 = df['CVSS V3 Vector'].str.split('/', expand=True)
new_df2 = df['CVSS Results'].str.split('/', expand=True)

df[['Vetor de Ataque',
    'Complexidade do Ataque',
    'Requer Privilégio',
    'Interação com Usuário',
    'Escopo',
    'Impacto na Confidencialidade',
    'Impacto na Integridade',
    'Impacto na Disponibilidade',
    'Maturidade do Exploit',
    'Nível de Remediação',
    'Confiança no relatório']] = new_df1

df[['Vetor de Ataque_2',
    'Complexidade do Ataque_2',
    'Autenticação',
    'Impacto na Confidencialidade_2',
    'Impacto na Integridade_2',
    'Impacto na Disponibilidade_2',
    'Maturidade do Exploit_2',
    'Nível de Remediação_2',
    'Confiança no relatório_2'
    ]] = new_df2

df['Vetor de Ataque'] = df['Vetor de Ataque'].fillna(
    df['Vetor de Ataque_2'])
df['Complexidade do Ataque'] = df['Complexidade do Ataque'].fillna(
    df['Complexidade do Ataque_2'])
df['Impacto na Confidencialidade'] = df['Impacto na Confidencialidade'].fillna(
    df['Impacto na Confidencialidade_2'])
df['Impacto na Integridade'] = df['Impacto na Integridade'].fillna(
    df['Impacto na Integridade_2'])
df['Impacto na Disponibilidade'] = df['Impacto na Disponibilidade'].fillna(
    df['Impacto na Disponibilidade_2'])
df['Maturidade do Exploit'] = df['Maturidade do Exploit'].fillna(
    df['Maturidade do Exploit_2'])
df['Nível de Remediação'] = df['Nível de Remediação'].fillna(
    df['Nível de Remediação_2'])
df['Confiança no relatório'] = df['Confiança no relatório'].fillna(
    df['Confiança no relatório_2'])

df.drop(df.filter(regex='_2$').columns.tolist(), axis=1, inplace=True)
df.drop(df.filter(regex='CVSS Results').columns.tolist(), axis=1, inplace=True)
df.drop(df.index[df['CVSS Agrupado'] == 'E:POC/RL:OF/RC:C'], inplace = True)

df['Impacto na Disponibilidade'] = df['Impacto na Disponibilidade'].replace(
    ['A:C', 'A:H', 'A:L', 'A:N', 'A:P'], ['Completo', 'Alto', 'Baixo', 'Nenhum', 'Parcial'])
df['Complexidade do Ataque'] = df['Complexidade do Ataque'].replace(
    ['AC:H', 'AC:L', 'AC:M'], ['Alto', 'Baixo', 'Médio'])
df['Autenticação'] = df['Autenticação'].replace(
    ['Au:M', 'Au:N', 'Au:S'], ['Multiplos', 'Nenhum', 'Único'])
df['Vetor de Ataque'] = df['Vetor de Ataque'].replace(
    ['AV:A', 'AV:L', 'AV:N', 'AV:P'], ['Adjacente', 'Local', 'Rede', 'Física'])
df['Impacto na Confidencialidade'] = df['Impacto na Confidencialidade'].replace(
    ['C:C', 'C:H', 'C:L', 'C:N', 'C:P'], ['Completo', 'Alto', 'Baixo', 'Nenhum', 'Parcial'])
df['Maturidade do Exploit'] = df['Maturidade do Exploit'].replace(['E:F', 'E:H', 'E:ND', 'E:P', 'E:POC', 'E:U', 'E:X'], [
                                                                'Funcional', 'Alto', 'Não Definido', 'Prova de conceito', 'Prova de Conceito', 'Não comprovado', 'Não definido'])
df['Impacto na Integridade'] = df['Impacto na Integridade'].replace(
    ['I:C', 'I:H', 'I:L', 'I:N', 'I:P'], ['Completo', 'Alto', 'Baixo', 'Nenhum', 'Parcial'])
df['Requer Privilégio'] = df['Requer Privilégio'].replace(
    ['PR:H', 'PR:L', 'PR:N'], ['Alto', 'Baixo', 'Nenhum'])
df['Confiança no relatório'] = df['Confiança no relatório'].replace(['RC:C', 'RC:ND', 'RC:R', 'RC:U', 'RC:UC', 'RC:UR', 'RC:X', ], [
                                                                    'Confirmado', 'Não definido', 'Razoável', 'Desconhecido', 'Não confirmado', 'Não corroborado', 'Não definido', ])
df['Nível de Remediação'] = df['Nível de Remediação'].replace(['RL:ND', 'RL:O', 'RL:OF', 'RL:T', 'RL:TF', 'RL:U', 'RL:W', 'RL:X'], [
                                                            'Não definido', 'Correção oficial', 'Correção oficial', 'Correção temporária', 'Correção temporária', 'Indisponível', 'Solução alternativa', 'Não definido'])
df['Escopo'] = df['Escopo'].replace(
    ['S:C', 'S:U'], ['Alterado', 'Inalterado'])
df['Interação com Usuário'] = df['Interação com Usuário'].replace(
    ['UI:N', 'UI:R'], ['Nenhuma', 'Requer'])

column_names = [
    "Plugin",
    "Plugin Name",
    "Family",
    "Severity",
    "IP Address",
    "Protocol",
    "Port",
    "Exploit?",
    "Repository",
    "MAC Address",
    "DNS Name",
    "NetBIOS Name",
    "Plugin Text",
    "First Discovered",
    "Last Observed",
    "Exploit Frameworks",
    "Synopsis",
    "Description",
    "Solution",
    "See Also",
    "Risk Factor",
    "STIG Severity",
    "Vulnerability Priority Rating",
    "CVSS V2 Base Score",
    "CVSS V3 Base Score",
    "CVSS V2 Temporal Score",
    "CVSS V2 Vector",
    "CVSS V3 Vector",
    "CVSS Agrupado",
    "Vetor de Ataque",
    "Complexidade do Ataque",
    "Requer Privilégio",
    "Interação com Usuário",
    "Escopo",
    "Impacto na Confidencialidade",
    "Impacto na Integridade",
    "Impacto na Disponibilidade",
    "Maturidade do Exploit",
    "Nível de Remediação",
    "Confiança no relatório",
    "Autenticação",
    "CPE",
    "CVE",
    "BID",
    "Cross References",
    "Vuln Publication Date",
    "Patch Publication Date",
    "Plugin Publication Date",
    "Plugin Modification Date",
    "Exploit Ease",
    "Check Type",
    "Version"]

df = df.reindex(columns=column_names)

print("Arquivo selecionado: " + excel1)
#print("Path: " + dir_path)

nome_arquivo = input('Escolha um nome para o arquivo: ')

if (os.path.exists(nome_arquivo + '.xlsx')) == True:
    print("O Arquivo já existe no diretório")
else:
    df.to_excel(nome_arquivo + '.xlsx', index=False)
    print("Arquivo gerado com sucesso")

print('Gerando Tabela Dinâmica')
for i in range(10,0,-1):
    time.sleep(1)
    print(i)

pivot_file = nome_arquivo
excel = win32com.client.gencache.EnsureDispatch('Excel.Application')
win32c = win32com.client.constants

path_pivot = dir_path + '\\'
wbxlsx = path_pivot + pivot_file + '.xlsx'
wb = excel.Workbooks.Open(wbxlsx)
ws = wb.Worksheets('Sheet1')
ws.Select()

PivotSourceRange = ws.Range("A1:AZ5000")
PivotTableName = 'ReportPivotTable'
PivotSourceRange.Select()

PivotSheet = wb.Worksheets.Add()
PivotSheet.Name = 'PivotTable'
pivotRange = PivotSheet.Range("A4")
PivotCache = wb.PivotCaches().Create(SourceType=win32c.xlDatabase, SourceData=PivotSourceRange, Version=win32c.xlPivotTableVersion14)
PivotTable = PivotCache.CreatePivotTable(TableDestination=pivotRange, TableName=PivotTableName, DefaultVersion=win32c.xlPivotTableVersion14)
PivotTable.PivotFields('DNS Name').Orientation = win32c.xlRowField
PivotTable.PivotFields('DNS Name').Position = 1
PivotTable.PivotFields('Vetor de Ataque').Orientation = win32c.xlRowField
PivotTable.PivotFields('Vetor de Ataque').Position = 2
PivotTable.PivotFields('Complexidade do Ataque').Orientation = win32c.xlRowField
PivotTable.PivotFields('Complexidade do Ataque').Position = 3
PivotTable.PivotFields('Requer Privilégio').Orientation = win32c.xlRowField
PivotTable.PivotFields('Requer Privilégio').Position = 4
PivotTable.PivotFields('Interação com Usuário').Orientation = win32c.xlRowField
PivotTable.PivotFields('Interação com Usuário').Position = 5
PivotTable.PivotFields('Maturidade do Exploit').Orientation = win32c.xlRowField
PivotTable.PivotFields('Maturidade do Exploit').Position = 6
PivotTable.PivotFields('Exploit?').Orientation = win32c.xlPageField
PivotTable.PivotFields('Exploit?').Position = 1
PivotTable.PivotFields('Exploit?').CurrentPage = 'Yes'
wb = PivotTable.AddDataField(PivotTable.PivotFields('Plugin Name'))

excel.Visible = False

excel.ActiveWorkbook.Save()
excel.Quit()
print('Tabela dinâmica gerada com sucesso')
time.sleep(2)
