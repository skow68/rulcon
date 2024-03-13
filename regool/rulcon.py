"""Algorytmy optymalizujące reguły.
Podczas modyfikacji rule_construct należy odkomentować fragmenty wyświetlające tabele texttable.
Bez tego trudno zrozumieć algorytm.
Jak są agregowane reguły:
1. first opt: many to one, one to many - tutaj jeszcze nie tworzymy kompromisów
- tworzymy dwie tabele - jedna z pojedynczymi dst, druga z pojedynczymi src; to który adres zostanie umieszczony
jako pojedynczy zależy od tego jak wiele adresów ma mieć dostęp do niego (dst) lub do jak wielu adresów ma być
dostęp od niego (src).
2. second opt - tutaj też nie mamy jeszcze kompromisów
- w przypadku tabeli z pojedynczymi dst grupujemy dst z taką samą listą src
- w przypadku tabeli z pojedynczymi src grupujemy src z taką samą listą dst
3. third opt - tu już mamy kompromis
- do tej pory elementy dst były parami ip:port, teraz te porty grupujemy w każdym wierszu.
Zakladamy, że port w postaci nienumerycznej oznacza nie port, ale aplikację i może kryć się pod tą nazwą więcej niż
jedna aplikacja. Dla tych przypadków tworzone są oddzielne reguły. Nazwy z kluczy słownika są predefiniowane we wniosku
o dostęp.
"""
import texttable
from collections import defaultdict
# z tym jeszcze nic nie jest zrobione;
apps = {
    'nfs': ['nfs', 'mount', 'portmaper'],
    'samba': ['ms-ds-smb']
}
"""
workbook = openpyxl.load_workbook("local.xlsx")
worksheet = workbook['Arkusz1']
my_dns = {}
for row in worksheet.iter_rows(values_only=True, min_row=3):
    my_dns[row[1]] = row[0]
    my_dns[row[2]] = row[3]
"""


def rule_factory(routetable):
    """Tworzenie struktury, która będzie wejściem do funkcji wykonującej konfigurację firewall'a.
    :param routetable: Lista list (tabela). Surowe dostępy z wniosku uzupełnione o zony i FW.
    :returns: Słownik - kluczem jest FW, a wartością lista list (tabela) z kompletem danych dla FW.
    """
    rule_paths = defaultdict(list)
    # kluczem jest dev i zony, bo dla tej trójki reguły muszą być oddzielne
    for r in routetable:
        rule_paths[str([r[0], r[2], r[4]])].append([r[1], r[3], r[5]])
    # ----presentation
    """ table = texttable.Texttable()
    table.set_max_width(140)
    for r in rule_paths:
        table.add_row([r, rule_paths[r]])
    print("ROUTEPATHS")
    print(table.draw()) """
    # ----------------
    
    ready_for_edge = {}
    for r_path, r in rule_paths.items():
        rulset = rule_construct(r)
        # rulset - zoptymalizowane reguły
        list_r_path = eval(r_path)
        # formatowanie wyjścia: zone src, zone dst, ip src, ip dst, port
        rulset_formated = [list_r_path[1:] + x for x in rulset]
        # wyjście jest słownikiem, gdzie kluczem jest dev.
        if list_r_path[0] in ready_for_edge:
            rulset_formated.append(ready_for_edge[list_r_path[0]])
            ready_for_edge[list_r_path[0]] = rulset_formated
        else:
            ready_for_edge[list_r_path[0]] = rulset_formated
    # ----presentation
    """ print("READY FOR EDGE")
    print("Uwaga: Wydruk nie odpowiada w pełni zwracanej strukturze, ale treść jest ok")
    for r in ready_for_edge:
        for rr in ready_for_edge[r]:
            print(r, ":")
            for rrr in rr:
                print("\t", rrr) """
    # ----------------
    return ready_for_edge


def rule_construct(basetable):
    """Agegacja/optymalizacja reguł
    :param basetable:  Lista list (tabela) src_ip, dst_ip, port. Surowe dane z wniosku.
    :returns: Znormalizowane reguły według przjętych przez nas zasad (m.in. deduplikacja i agregacja). 
            Struktura - lista list (tabela), a każda komórka tabeli to też lista. 
            [[[src_table], [dst_table], [port_table], [service_table]], ...]
    """
    by_dst = defaultdict(list)
    by_src = defaultdict(list)
    src = []
    dst = []
    for row in basetable:
        #  budujemy dwa słowniki:
        #  -  kluczem jest każdy dst, wartością jest lista src, które mają mieć do niego dostęp
        #  -  kluczem jest każdy src, wartościąjest lista dst, do których ma mieć dostęp
        # czyli reguły są zdublowane
        dst = str(row[1]) + ":" + str(row[2])
        src = row[0]
        by_dst[dst].append(src)
        by_src[src].append(dst)

    tabledst = texttable.Texttable()
    for d in by_dst:
        tabledst.add_row([d, by_dst[d]])
    tablesrc = texttable.Texttable()
    for s in by_src:
        tablesrc.add_row([s, by_src[s]])
    """ print("Before opt")
    print(tabledst.draw())
    print()
    print(tablesrc.draw()) """

    # First opt
    # w/g zasady: liczba src w tabeli by_dst i liczba dst w tabeli by_src są decydujące; pierwszeństwo ma ta reguła,
    # dla której ta liczba jest większa; chodzi o to, aby zgrupować w jednej regule jak najwięcej ip, czy to src,
    # czy dst. Znika też zdublowanie reguł z poprzedniego punktu.
    for d in by_dst:
        tmp_dst = []
        for s in by_dst[d]:
            if len(by_src[s]) < len(by_dst[d]):
                by_src[s].remove(d)
            else:
                # by_dst[d].remove(s)
                tmp_dst.append(s)
        tmp_dst = list(set(tmp_dst))
        # ta pętla jest tylko dlatego, że nie można usuwać elementów z listy by_dst[d] w poprzedniej pętli,
        # bo iteracja idzie właśnie po tej liście
        for ss in tmp_dst:
            by_dst[d].remove(ss)
    # Usuwanie par w dict, dla których value jest tablicą pustą:
    delete = [key for key in by_dst if by_dst[key] == []]
    for key in delete:
        del by_dst[key]
    delete = [key for key in by_src if by_src[key] == []]
    for key in delete:
        del by_src[key]
    # ----presentation
    """    print("After first opt")
    tabledst = texttable.Texttable()
    for d in by_dst:
        tabledst.add_row([by_dst[d], d])
    print(tabledst.draw())
    print()
    tablesrc = texttable.Texttable()
    for s in by_src:
        tablesrc.add_row([s, by_src[s]])
    print(tablesrc.draw()) """
    # ----presentation
    
    #  Second opt
    # Scalanie reguł, gdzie src i dst są takie same, a różnią się tylko porty
    # Tworzony jest hash, które kluczem jest lista src z poprzedniej optymalizacji, a wartością lista par ipdst:port
    # Z tym że ipdst jest taki sam, różne są tylko porty.
    # tabela by_dst:
    by_dstip = defaultdict(list)
    # dst ip -> lista portów
    for d in by_dst.keys():
        [ip, port] = d.split(":")
        by_dstip[ip].append(port)
    by_srclist = defaultdict(list)
    for dip in by_dstip:
        for port in by_dstip[dip]:
            dst_ipport = dip + ":" + port
            # kluczem jest lista
            src_ip_lst = str(by_dst[dst_ipport])
            by_srclist[src_ip_lst].append(dst_ipport)
    # uwaga: elementy by_srclist to str
    
    """ tabledst = texttable.Texttable()
    for slst in by_srclist:
        tabledst.add_row([slst, by_srclist[slst]])
    print("After second opt")
    print(tabledst.draw()) """
    
    # tabela by_src:
    # z tabelą by_src jest łatwiej bo strona src nie zawiera portów;
    by_dstlist = defaultdict(list)
    for s in by_src.keys():
        # kluczem jest lista
        by_dstlist[str(by_src[s])].append(s)
    tablesrc = texttable.Texttable()
    for dlst in by_dstlist:
        tablesrc.add_row([by_dstlist[dlst], dlst])
    # print(tablesrc.draw())
    # Ponieważ nie będziemy już operować na adresach, łączymy słowniki by_dstlist i by_srclist
    # przedtem by_dstlist musimy odwrócić, tak aby w obu w słownikach kluczem był src (a nie dst? - do sprawdzenie).
    rev_by_dstlist = {}
    for item in by_dstlist.items():
        key = str(item[1])
        val = item[0]
        val = val.replace('[\'', '').replace('\']', '')
        # .replace("']", '')
        rev_by_dstlist[key] = val.split("\', \'")
    # rev_by_srclist = {val: key for (key, val) in by_srclist.items()}
    # łączenie dict:
    rule_form_1 = {**by_srclist, **rev_by_dstlist}
    
    """ tableform1 = texttable.Texttable()
    for lst in rule_form_1:
        tableform1.add_row([lst, rule_form_1[lst]])
    print("As before, but in one table")
    print(tableform1.draw()) """
    
    # Third opt
    # Tu już mamy kompromis. Wyłuskanie portów z każdego wiersza i wrzucenie do wspólnego worka. 
    # Oddzielnie są wyłuskiwane nazwy usług (port_apps_list). Dla nich będą tworzone oddzielne reguły.
    rule_form_2 = []
    for src_lst, dst_lst in rule_form_1.items():
        ip_list = []
        ip_apps_list = []
        port_list = []
        port_apps_list = []
        for dst_ipport in dst_lst:
            [ip, port] = dst_ipport.split(":")
            if port in apps.keys():
                port_apps_list.append(port)
                ip_apps_list.append(ip)
            else:
                port_list.append(port)
                ip_list.append(ip)
        ip_list = list(set(ip_list))
        port_list = list(set(port_list))
        port_apps_list = list(set(port_apps_list))
        ip_apps_list = list(set(ip_apps_list))
        src_lst = eval(src_lst)
        if port_list:
            rule_form_2.append([src_lst, ip_list, port_list, ""])
        if port_apps_list:
            rule_form_2.append([src_lst, ip_apps_list, "", port_apps_list])
    #----presentation
    tableform2 = texttable.Texttable()
    for lst in rule_form_2:
        tableform2.add_row([lst[0], lst[1], lst[2], lst[3]])
    print("THIRD OPT")
    print(tableform2.draw())
    #----presentation
    return(rule_form_2)
    """
        print('srcname', row[0])
        print('srcaddress', row[1])
        print('dstname', row[2])
        print('dstaddress', row[3])
        print('port', row[4])
        print("\n\n")
    """


# opti_rules = rule_construct(worksheet)
# tableform2 = texttable.Texttable()
# for lst in opti_rules:
#     tableform2.add_row([lst[0], lst[1], lst[2], lst[3]])
# print("Final table:")
# print(tableform2.draw())
# print(opti_rules)

